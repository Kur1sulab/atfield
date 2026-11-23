package api

// stream.go —— /api/stream：SSE 推送 overview。
//
// 为什么用 SSE 而不是 WebSocket：控制台的需求就是「每两秒一份新快照」，
// 单向、可断线重连、走普通 HTTP（能穿大多数反代），不需要握手与心跳协商。
// Python 版用的是同一个方案（2 秒一帧、300 秒上限），这里保持完全一致，
// 前端 EventSource 不用改一行。
//
// 300 秒上限的作用是让反代/浏览器的连接不会无限堆积：到点服务端主动结束，
// 前端 EventSource 自己会重连。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// streamInterval 推帧间隔（Python 同：time.sleep(2)）。
const streamInterval = 2 * time.Second

// streamDeadline 单连接最长存活时间（Python 同：300 秒）。
const streamDeadline = 300 * time.Second

// handleStream SSE 端点。头部与 Python _sse 一致。
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if s.guard(w, r, "read") == nil {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		// 理论上 net/http 的 ResponseWriter 永远实现 Flusher；真遇到不支持的
		// 包装器（某些中间件）就直接拒绝，免得客户端收到一坨攒着的半截数据。
		writeErr(w, http.StatusInternalServerError, "当前 ResponseWriter 不支持流式输出")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	deadline := time.Now().Add(streamDeadline)
	tick := time.NewTicker(streamInterval)
	defer tick.Stop()

	for {
		payload := s.overviewJSON()
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return // 客户端断了
		}
		fl.Flush()

		if time.Now().After(deadline) {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

// overviewJSON 序列化一份 overview。失败时给一个最小错误帧——
// 绝不让 SSE 断流（前端会以为后端挂了，反而看不到真实错误）。
func (s *Server) overviewJSON() (out []byte) {
	defer func() {
		// overview 里有一堆 map/any 访问，理论上不该 panic；
		// 但一个 panic 会带走整个连接甚至进程，这里兜住并降级成一个错误帧。
		if rec := recover(); rec != nil {
			out = []byte(`{"error":"overview failed"}`)
		}
	}()
	b, err := json.Marshal(s.buildOverview())
	if err != nil {
		return []byte(`{"error":"overview failed"}`)
	}
	return b
}
