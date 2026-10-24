package agent

// 批 5 B4(设计文档 HONEYPOT-DETECTION-DESIGN.md 二-B「自身防护」第 4 条):客户端 UA 池。
// 野样本里蜜罐的触发器正是「UA/TLS 指纹失配」——裸 Chrome UA + curl TLS 的半吊子
// 伪装不如不装。平台统一按任务稳定分配一个客户端 UA,经 BashEnv 注入 ARTEX_UA,
// worker 的 HTTP 客户端(curl/httpx 等)整任务使用同一个,不乱换、不半伪装。

import (
	"encoding/binary"
	"encoding/json"
	"hash/fnv"
	"strings"
)

// DefaultUAPool 是 settings 键 web_ua_pool 未配置时的默认池:两个如实标识 ARTEX 的客户端 UA。
func DefaultUAPool() []string {
	return []string{"ARTEX/2.2 (+authorized-assessment)", "ARTEX/2.2 (+security-audit)"}
}

// UAPoolFromSetting 解析 settings 键 web_ua_pool(JSON 字符串数组);空/非法/
// 解析后无有效条目时回落默认池。
func UAPoolFromSetting(raw string) []string {
	var pool []string
	if err := json.Unmarshal([]byte(raw), &pool); err == nil {
		out := make([]string, 0, len(pool))
		for _, ua := range pool {
			if ua = strings.TrimSpace(ua); ua != "" && len(ua) <= 512 && !strings.ContainsAny(ua, "\r\n\x00") {
				out = append(out, ua)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return DefaultUAPool()
}

// PickUA 按任务稳定分配:hash(taskID) % len(pool)。同一任务永远拿到同一个 UA
// (任务内不更换是纪律的一部分);pool 为空回落默认池。
func PickUA(pool []string, taskID int64) string {
	if len(pool) == 0 {
		pool = DefaultUAPool()
	}
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(taskID))
	_, _ = h.Write(buf[:])
	return pool[h.Sum64()%uint64(len(pool))]
}
