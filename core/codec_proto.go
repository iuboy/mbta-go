package core

import (
	"fmt"
	"math"
	"reflect"
	"strconv"

	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// protoCodec 以 Protobuf wire 格式编解码 SignalBatch（默认 codec）。
//
// 这是唯一经 corepb AnyValue oneof 表达动态类型（attributes/body）的 codec：
// wire 紧凑、跨语言代码生成、与 OTLP schema 直接互通。Marshal 使用 Deterministic
// 选项（map 按键排序序列化）——proto.Marshal 默认迭代序非确定，canonical 字节
// 是未来 canonical HMAC 的前提（与 cbor 侧 CanonicalEncOptions 对称）。
type protoCodec struct{}

func (protoCodec) Codec() corepb.Codec { return corepb.Codec_CODEC_PROTO }

func (protoCodec) Marshal(sb *SignalBatch) ([]byte, error) {
	pb := toProtoSignalBatch(sb)
	return proto.MarshalOptions{Deterministic: true}.Marshal(pb)
}

func (protoCodec) Unmarshal(data []byte) (*SignalBatch, error) {
	// 条数预检发生在 proto.Unmarshal 全量分配之前：proto 对 repeated 字段无
	// 解码上限，8MB payload 的最小合法 record（11 wire 字节）可在条数检查前
	// 解出 76 万条 × 双层结构（corepb+core 各一份）≈ 537MB 堆——validate-after-decode
	// 放大窗口与 cbor 侧 MaxArrayElements 的裁决对称，proto 是默认 codec 更须封堵。
	if err := checkProtoSignalCount(data); err != nil {
		return nil, err
	}
	var pb corepb.SignalBatch
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, WrapError(ErrCodeBatchInvalid, "unmarshal signal batch", err)
	}
	// 其余内容合法性（signal_type 闭合枚举/字段长度等）由调用方的 sb.Validate()
	// 统一负责——生产路径在 internal/protocol handler_batch.decodeAndValidate
	// 接线，codec 层不重复（cbor codec 同样无此检查，保持一致）。
	return fromProtoSignalBatch(&pb), nil
}

// MaxProtoSignals 是 proto codec 对 SignalBatch.signals（field 4）的条数解码上限，
// 与 internal/protocol 的 maxBatchEvents 同值（codec 层不 import 上层常量，值由
// conformance 对齐测试钉住）。
const MaxProtoSignals = 10000

// checkProtoSignalCount 预扫 wire 统计 signals 字段（field 4，BytesType）出现
// 次数并在超限时拒绝——发生在全量解码分配之前（8MB 预扫约 10ms）。malformed
// wire 在此报错与 proto.Unmarshal 的拒绝语义一致，不改变原有错误分类。
func checkProtoSignalCount(data []byte) error {
	count := 0
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return WrapError(ErrCodeBatchInvalid, "scan signal batch", protowire.ParseError(n))
		}
		data = data[n:]
		fn := protowire.ConsumeFieldValue(num, typ, data)
		if fn < 0 {
			return WrapError(ErrCodeBatchInvalid, "scan signal batch", protowire.ParseError(fn))
		}
		if num == signalsFieldNum && typ == protowire.BytesType {
			count++
			if count > MaxProtoSignals {
				return NewError(ErrCodeBatchInvalid,
					fmt.Sprintf("signal count exceeds codec decode limit %d", MaxProtoSignals))
			}
		}
		data = data[fn:]
	}
	return nil
}

// signalsFieldNum 是 SignalBatch.signals 的 proto 字段号（proto/signal.proto）。
const signalsFieldNum = 4

func init() {
	RegisterCodec(protoCodec{})
}

// --- proto 转换 helpers ---

func toProtoSignalBatch(sb *SignalBatch) *corepb.SignalBatch {
	pb := &corepb.SignalBatch{
		SchemaUrl: sb.SchemaURL,
		Signals:   make([]*corepb.SignalRecord, len(sb.Signals)),
	}
	if len(sb.Resource.Attributes) > 0 {
		pb.Resource = &corepb.Resource{
			Attributes: anyMapToProto(sb.Resource.Attributes),
		}
	}
	if sb.Scope.Name != "" || sb.Scope.Version != "" || sb.Scope.CollectorID != "" {
		pb.Scope = &corepb.InstrumentationScope{
			Name:        sb.Scope.Name,
			Version:     sb.Scope.Version,
			CollectorId: sb.Scope.CollectorID,
		}
	}
	for i, s := range sb.Signals {
		pb.Signals[i] = toProtoSignalRecord(s)
	}
	return pb
}

func toProtoSignalRecord(s *SignalRecord) *corepb.SignalRecord {
	pb := &corepb.SignalRecord{
		SignalType:         s.SignalType,
		EventId:            s.EventID,
		TimeUnixNs:         s.TimeUnixNs,
		ObservedTimeUnixNs: s.ObservedTimeNs,
		TraceId:            s.TraceID,
		SpanId:             s.SpanID,
		ParentSpanId:       s.ParentSpanID,
		Body:               anyToProtoValue(s.Body),
		SeverityNumber:     int32(s.SeverityNumber),
		SeverityText:       s.SeverityText,
		MetricName:         s.MetricName,
		Unit:               s.Unit,
		Temporality:        s.Temporality,
		IsMonotonic:        s.IsMonotonic,
		Name:               s.Name,
		Kind:               s.Kind,
		StartTimeUnixNs:    s.StartTimeUnixNs,
		EndTimeUnixNs:      s.EndTimeUnixNs,
		StatusCode:         s.StatusCode,
		StatusMessage:      s.StatusMessage,
	}
	if len(s.Attributes) > 0 {
		pb.Attributes = anyMapToProto(s.Attributes)
	}
	if len(s.MetricFields) > 0 {
		pb.MetricFields = make(map[string]float64, len(s.MetricFields))
		for k, v := range s.MetricFields {
			pb.MetricFields[k] = v
		}
	}
	// W3C Trace Context（capability trace_context）。
	pb.TraceFlags = s.TraceFlags
	if len(s.TraceState) > 0 {
		pb.TraceState = make([]*corepb.TraceStateEntry, len(s.TraceState))
		for i, e := range s.TraceState {
			pb.TraceState[i] = &corepb.TraceStateEntry{Key: e.Key, Value: e.Value}
		}
	}
	// Exponential histogram / Profile 载荷（OTLP 映射见规范附录 B）。
	pb.ExpHistogram = s.ExpHistogram
	pb.Profile = s.Profile
	return pb
}

func fromProtoSignalBatch(pb *corepb.SignalBatch) *SignalBatch {
	sb := &SignalBatch{
		SchemaURL: pb.GetSchemaUrl(),
		Signals:   make([]*SignalRecord, len(pb.GetSignals())),
	}
	if pb.GetResource() != nil {
		sb.Resource.Attributes = protoMapToAny(pb.GetResource().GetAttributes())
	}
	if pb.GetScope() != nil {
		sb.Scope.Name = pb.GetScope().GetName()
		sb.Scope.Version = pb.GetScope().GetVersion()
		sb.Scope.CollectorID = pb.GetScope().GetCollectorId()
	}
	for i, s := range pb.GetSignals() {
		sb.Signals[i] = fromProtoSignalRecord(s)
	}
	return sb
}

func fromProtoSignalRecord(s *corepb.SignalRecord) *SignalRecord {
	r := &SignalRecord{
		SignalType:      s.GetSignalType(),
		EventID:         s.GetEventId(),
		TimeUnixNs:      s.GetTimeUnixNs(),
		ObservedTimeNs:  s.GetObservedTimeUnixNs(),
		TraceID:         s.GetTraceId(),
		SpanID:          s.GetSpanId(),
		ParentSpanID:    s.GetParentSpanId(),
		Body:            protoValueToAny(s.GetBody()),
		SeverityNumber:  int(s.GetSeverityNumber()),
		SeverityText:    s.GetSeverityText(),
		MetricName:      s.GetMetricName(),
		Unit:            s.GetUnit(),
		Temporality:     s.GetTemporality(),
		IsMonotonic:     s.GetIsMonotonic(),
		Name:            s.GetName(),
		Kind:            s.GetKind(),
		StartTimeUnixNs: s.GetStartTimeUnixNs(),
		EndTimeUnixNs:   s.GetEndTimeUnixNs(),
		StatusCode:      s.GetStatusCode(),
		StatusMessage:   s.GetStatusMessage(),
	}
	if len(s.GetAttributes()) > 0 {
		r.Attributes = protoMapToAny(s.GetAttributes())
	}
	if len(s.GetMetricFields()) > 0 {
		r.MetricFields = make(map[string]float64, len(s.GetMetricFields()))
		for k, v := range s.GetMetricFields() {
			r.MetricFields[k] = v
		}
	}
	// W3C Trace Context（capability trace_context）。
	r.TraceFlags = s.GetTraceFlags()
	if ts := s.GetTraceState(); len(ts) > 0 {
		r.TraceState = make([]*TraceStateEntry, len(ts))
		for i, e := range ts {
			r.TraceState[i] = &TraceStateEntry{Key: e.GetKey(), Value: e.GetValue()}
		}
	}
	// Exponential histogram / Profile 载荷（OTLP 映射见规范附录 B）。
	r.ExpHistogram = s.GetExpHistogram()
	r.Profile = s.GetProfile()
	return r
}

func anyToProtoValue(v any) *corepb.AnyValue {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return &corepb.AnyValue{Value: &corepb.AnyValue_StringValue{StringValue: val}}
	case int:
		return &corepb.AnyValue{Value: &corepb.AnyValue_IntValue{IntValue: int64(val)}}
	case int64:
		return &corepb.AnyValue{Value: &corepb.AnyValue_IntValue{IntValue: val}}
	case float64:
		return &corepb.AnyValue{Value: &corepb.AnyValue_DoubleValue{DoubleValue: val}}
	case bool:
		return &corepb.AnyValue{Value: &corepb.AnyValue_BoolValue{BoolValue: val}}
	case []byte:
		return &corepb.AnyValue{Value: &corepb.AnyValue_BytesValue{BytesValue: val}}
	default:
		// 用 reflect 匹配所有整数/浮点 kind，避免 int32/uint64/float32 等静默降级为 string。
		// 注意：不要用 rv.IsZero() 过滤——零值（int32(0)、uint64(0)）是合法数值，
		// 必须按数值类型序列化，否则同一字段的 0 与非 0 会落到不同 oneof 分支。
		if rv := reflect.ValueOf(v); rv.IsValid() {
			switch rv.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				return &corepb.AnyValue{Value: &corepb.AnyValue_IntValue{IntValue: rv.Int()}}
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				u := rv.Uint()
				// 超出 int64 范围时回退到字符串，避免溢出为负数导致数据损坏。
				if u > math.MaxInt64 {
					return &corepb.AnyValue{Value: &corepb.AnyValue_StringValue{StringValue: strconv.FormatUint(u, 10)}}
				}
				return &corepb.AnyValue{Value: &corepb.AnyValue_IntValue{IntValue: int64(u)}}
			case reflect.Float32, reflect.Float64:
				return &corepb.AnyValue{Value: &corepb.AnyValue_DoubleValue{DoubleValue: rv.Float()}}
			default:
				// 其余 kind（bool/string/slice/map/struct 等）已在上方 type switch 处理，
				// 到此说明是不支持的复杂类型，落到下方 fmt.Sprintf。
			}
		}
		return &corepb.AnyValue{Value: &corepb.AnyValue_StringValue{StringValue: fmt.Sprintf("%v", v)}}
	}
}

func protoValueToAny(av *corepb.AnyValue) any {
	if av == nil {
		return nil
	}
	switch v := av.GetValue().(type) {
	case *corepb.AnyValue_StringValue:
		return v.StringValue
	case *corepb.AnyValue_IntValue:
		return v.IntValue
	case *corepb.AnyValue_DoubleValue:
		return v.DoubleValue
	case *corepb.AnyValue_BoolValue:
		return v.BoolValue
	case *corepb.AnyValue_BytesValue:
		return v.BytesValue
	default:
		return nil
	}
}

func anyMapToProto(m map[string]any) map[string]*corepb.AnyValue {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]*corepb.AnyValue, len(m))
	for k, v := range m {
		result[k] = anyToProtoValue(v)
	}
	return result
}

func protoMapToAny(m map[string]*corepb.AnyValue) map[string]any {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]any, len(m))
	for k, v := range m {
		result[k] = protoValueToAny(v)
	}
	return result
}
