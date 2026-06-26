package protocol

// SetRedirectHandler registers a callback invoked when the server sends a
// TypeRedirect frame (S→C cluster redirect). The callback receives the raw
// frame payload; the application decodes it (e.g. JSON {leaderAddr, leaderId}).
// At most one handler is active; a later call replaces the prior one.
//
// Used by HA follower replicas to redirect agents to the elected leader.
func (c *CoreClient) SetRedirectHandler(h func(payload []byte)) {
	c.redirectHandler.Store(&h)
}

func (c *CoreClient) loadRedirectHandler() func(payload []byte) {
	if p := c.redirectHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// dispatchRedirect invokes the registered redirect handler synchronously.
// Redirect is rare (once per failover) so no worker queue is needed; a nil
// handler means the client ignores the frame (old clients pre-dating this
// feature).
func (c *CoreClient) dispatchRedirect(payload []byte) {
	if h := c.loadRedirectHandler(); h != nil {
		h(payload)
	}
}
