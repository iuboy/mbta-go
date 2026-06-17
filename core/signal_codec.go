package core

import (
	"fmt"

	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// MarshalSignalBatch 将 core.SignalBatch 序列化为 proto bytes（spec §6 codec=proto）。
// 替代旧 sonic JSON 编码——wire 更紧凑、跨语言、MAC 确定性。
func MarshalSignalBatch(sb *SignalBatch) ([]byte, error) {
	if sb == nil {
		return nil, NewError(NumValidation, CodeValidation, "nil signal batch")
	}
	pb := toProtoSignalBatch(sb)
	return proto.Marshal(pb)
}

// UnmarshalSignalBatch 从 proto bytes 解析 core.SignalBatch。
func UnmarshalSignalBatch(data []byte) (*SignalBatch, error) {
	if len(data) == 0 {
		return nil, NewError(NumValidation, CodeValidation, "empty signal batch data")
	}
	var pb corepb.SignalBatch
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, WrapError(NumValidation, CodeValidation, "unmarshal signal batch", err)
	}
	return fromProtoSignalBatch(&pb), nil
}

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
		TimeUnixMs:         s.TimeUnixMs,
		ObservedTimeUnixMs: s.ObservedTimeMs,
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
		StartTimeUnixMs:    s.StartTimeUnixMs,
		EndTimeUnixMs:      s.EndTimeUnixMs,
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
		TimeUnixMs:      s.GetTimeUnixMs(),
		ObservedTimeMs:  s.GetObservedTimeUnixMs(),
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
		StartTimeUnixMs: s.GetStartTimeUnixMs(),
		EndTimeUnixMs:   s.GetEndTimeUnixMs(),
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
