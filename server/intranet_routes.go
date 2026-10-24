package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/stage"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) sessionTaskContext(ctx context.Context, rec *db.SessionRecord) (context.Context, error) {
	src, ok := s.m.Task(strconv.FormatInt(rec.CreatedByTask, 10))
	if !ok || rec.CreatedByTask <= 0 {
		return ctx, fmt.Errorf("来源任务不存在")
	}
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return ctx, fmt.Errorf("缺少会话任务归属")
	}
	current, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10))
	if !ok {
		return ctx, fmt.Errorf("当前任务不存在")
	}
	allowed := current.ID == src.ID
	if !allowed {
		t, err := s.m.pg.GetTask(ri.TaskID)
		if err != nil {
			return ctx, err
		}
		if t != nil {
			for _, id := range t.SourceTaskIDs {
				if id == rec.CreatedByTask {
					allowed = true
				}
			}
		}
	}
	if !allowed {
		return ctx, fmt.Errorf("会话不属于当前任务或直接继承来源")
	}
	return ctx, nil
}
func (s *Server) checkRemoteCall(ctx context.Context, name string, input any) error {
	id := agent.RunInfoFrom(ctx).TaskID
	t, ok := s.m.Task(strconv.FormatInt(id, 10))
	if !ok {
		return fmt.Errorf("任务不存在")
	}
	raw, _ := json.Marshal(input)
	return t.Guard.CheckCall(ctx, name, raw)
}

// Manual requests use the source task's existing Guard and audit context.
func (s *Server) managedSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.intranetSessionsReady(w) {
			return
		}
		id, err := pathID(r, "id")
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		rec, err := s.sessStore.Get(r.Context(), id)
		if err != nil || rec == nil {
			writeErr(w, 404, "会话不存在")
			return
		}
		t, ok := s.m.Task(strconv.FormatInt(rec.CreatedByTask, 10))
		if !ok {
			writeErr(w, 409, "来源任务不存在")
			return
		}
		ctx := agent.WithRunInfo(r.Context(), agent.RunInfo{TaskID: rec.CreatedByTask, ExplorationID: t.ExpID})
		ctx = intercept.WithTaskContext(ctx, t.ID, "manual", nil)
		if _, err := s.sessionRoECheck(ctx, rec.URL); err != nil {
			writeErr(w, 403, err.Error())
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 90*1024*1024))
		if err != nil {
			writeErr(w, 400, "请求超出限制")
			return
		}
		var input map[string]any
		_ = json.Unmarshal(raw, &input)
		if input == nil {
			input = map[string]any{}
		}
		if content, ok := input["content_base64"].(string); ok {
			if data, err := base64.StdEncoding.DecodeString(content); err == nil {
				if err := s.stageContentCheck(data); err != nil {
					writeErr(w, 403, err.Error())
					return
				}
			}
		}
		input["url"] = rec.URL
		name := "session_write"
		if strings.HasSuffix(r.URL.Path, "/exec") {
			name = "Bash"
		}
		if err := s.checkRemoteCall(ctx, name, input); err != nil {
			writeErr(w, 403, err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next(w, r.WithContext(ctx))
	}
}
func (s *Server) registerIntranetRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/sessions", s.intranetListSessions)
	m.HandleFunc("POST /api/sessions", s.intranetRegisterSession)
	m.HandleFunc("GET /api/sessions/{id}", s.intranetGetSession)
	for pattern, fn := range map[string]http.HandlerFunc{
		"POST /api/sessions/{id}/exec":    s.intranetExec,
		"POST /api/sessions/{id}/probe":   s.intranetProbeSession,
		"POST /api/sessions/{id}/list":    s.intranetListDir,
		"POST /api/sessions/{id}/read":    s.intranetReadFile,
		"POST /api/sessions/{id}/write":   s.intranetWriteFile,
		"POST /api/sessions/{id}/recon":   s.intranetRecon,
		"POST /api/sessions/{id}/handoff": s.sessionHandoff,
	} {
		m.HandleFunc(pattern, s.managedSession(fn))
	}
	m.HandleFunc("DELETE /api/sessions/{id}", s.intranetDeleteSession)
	m.HandleFunc("GET /api/tunnels", s.intranetListTunnels)
	m.HandleFunc("POST /api/tunnels", s.intranetDeployTunnel)
	m.HandleFunc("POST /api/tunnels/{id}/teardown", s.intranetTeardownTunnel)
	m.HandleFunc("GET /api/credentials", s.intranetListCredentials)
	m.HandleFunc("POST /api/credentials", s.intranetAddCredential)
	m.HandleFunc("PATCH /api/credentials/{id}", s.intranetVerifyCredential)
	m.HandleFunc("GET /api/intranet/topology", s.intranetTopology)
	m.HandleFunc("GET /api/tasks/{id}/pending-scope", s.pendingScopeList)
	m.HandleFunc("POST /api/pending-scope/{id}/decide", s.pendingScopeDecide)
	m.HandleFunc("GET /api/stage", s.stageList)
	m.HandleFunc("POST /api/stage", s.stageCreate)
	m.HandleFunc("DELETE /api/stage/{token}", s.stageDelete)
}
func (s *Server) apiTaskContext(w http.ResponseWriter, r *http.Request, taskID int64) (context.Context, bool) {
	t, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok {
		writeErr(w, 400, "需要有效任务")
		return nil, false
	}
	ctx := agent.WithRunInfo(r.Context(), agent.RunInfo{TaskID: taskID, ExplorationID: t.ExpID})
	return intercept.WithTaskContext(ctx, t.ID, "manual", nil), true
}
func (s *Server) intranetRegisterSession(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	taskID, _ := in["task_id"].(float64)
	ctx, ok := s.apiTaskContext(w, r, int64(taskID))
	if !ok {
		return
	}
	raw, _ := json.Marshal(in)
	if err := s.checkRemoteCall(ctx, "register_session", in); err != nil {
		writeErr(w, 403, err.Error())
		return
	}
	result, err := s.registerSessionTool().Call(ctx, raw, nil)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeManagedResult(w, result)
}
func (s *Server) intranetRecon(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r, "id")
	raw, _ := json.Marshal(map[string]any{"session_id": id})
	result, err := s.sessionReconTool().Call(r.Context(), raw, nil)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeManagedResult(w, result)
}
func (s *Server) intranetDeployTunnel(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	taskID, _ := in["task_id"].(float64)
	ctx, ok := s.apiTaskContext(w, r, int64(taskID))
	if !ok {
		return
	}
	if s.tunnels == nil {
		writeErr(w, 503, "隧道未就绪")
		return
	}
	if err := s.checkRemoteCall(ctx, "tunnel_deploy", in); err != nil {
		writeErr(w, 403, err.Error())
		return
	}
	raw, _ := json.Marshal(in)
	result, err := s.tunnelDeployTool().Call(ctx, raw, nil)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeManagedResult(w, result)
}
func (s *Server) intranetAddCredential(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	taskID, _ := in["task_id"].(float64)
	ctx, ok := s.apiTaskContext(w, r, int64(taskID))
	if !ok {
		return
	}
	if s.credStore == nil {
		writeErr(w, 503, "凭据台账未就绪")
		return
	}
	raw, _ := json.Marshal(in)
	result, err := s.addCredentialTool().Call(ctx, raw, nil)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeManagedResult(w, result)
}
func (s *Server) intranetVerifyCredential(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var in struct {
		Verified bool   `json:"verified"`
		Reason   string `json:"reason"`
	}
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Reason) == "" {
		writeErr(w, 400, "需要验证结果和理由")
		return
	}
	if s.credStore == nil {
		writeErr(w, 503, "凭据台账未就绪")
		return
	}
	result, err := s.m.pg.ExecContext(r.Context(), `UPDATE credentials SET verified=$2,verification_reason=$3 WHERE id=$1`, id, in.Verified, strings.TrimSpace(in.Reason))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if affected, err := result.RowsAffected(); err != nil || affected == 0 {
		writeErr(w, 404, "凭据不存在")
		return
	}
	s.auditIntranet(r, "credential=%d verified=%v reason=%q", id, in.Verified, in.Reason)
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) stageContentCheck(data []byte) error {
	if int64(len(data)) > stage.MaxFileSize {
		return fmt.Errorf("文件超过 64 MiB")
	}
	if s.m.egress != nil {
		if _, hit := s.m.egress.Check(string(data)); hit {
			return fmt.Errorf("文件包含平台敏感材料，拒绝分发")
		}
	}
	return nil
}
func (s *Server) safeStageFile(path string, o stage.PutOpts) (*stage.Entry, error) {
	id, err := strconv.ParseInt(o.TaskID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("文件分发需要任务归属")
	}
	if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
		return nil, fmt.Errorf("任务不存在")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, base := range []string{filepath.Join(s.m.dir, "tasks", o.TaskID), filepath.Join(s.m.dir, "tools")} {
		real, err := filepath.EvalSymlinks(base)
		if err != nil {
			continue
		}
		real, _ = filepath.Abs(real)
		rel, err := filepath.Rel(real, resolved)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			allowed = true
		}
	}
	if !allowed {
		return nil, fmt.Errorf("只允许当前任务工作目录或已安装工具目录")
	}
	for _, part := range strings.Split(filepath.ToSlash(resolved), "/") {
		if part == ".secrets" || part == ".env" || strings.HasSuffix(part, ".key") || strings.HasSuffix(part, ".token") {
			return nil, fmt.Errorf("敏感路径不允许分发")
		}
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > stage.MaxFileSize {
		return nil, fmt.Errorf("只支持不超过 64 MiB 的普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, stage.MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if err = s.stageContentCheck(data); err != nil {
		return nil, err
	}
	return s.stage.PutContent(filepath.Base(resolved), data, o)
}

// Restore manually marked dead HTTP sessions only for an explicit authorized probe.
func (s *Server) restoreForProbe(ctx context.Context, id int64) (session.Session, error) {
	if sh, ok := s.sessReg.Get(id); ok {
		return sh, nil
	}
	rec, err := s.sessStore.Get(ctx, id)
	if err != nil || rec == nil {
		return nil, fmt.Errorf("会话不存在")
	}
	var sec session.Secret
	if err := json.Unmarshal(rec.Secret, &sec); err != nil {
		return nil, err
	}
	sh, err := session.RestoreHTTPShell(id, sec)
	if err == nil {
		s.sessReg.Add(sh)
	}
	return sh, err
}

func writeManagedResult(w http.ResponseWriter, result actool.Result) {
	if result.IsError {
		writeErr(w, 400, result.Flatten())
		return
	}
	var out any
	if json.Unmarshal([]byte(result.Flatten()), &out) != nil {
		out = map[string]any{"message": result.Flatten()}
	}
	writeJSON(w, 200, out)
}
