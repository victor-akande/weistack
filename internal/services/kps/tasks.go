package kps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	taskStatusRunning = "RUNNING"
	taskStatusSuccess = "SUCCESS"
	taskStatusFailed  = "FAILED"

	taskOpReset   = "RESET"
	taskOpReplace = "REPLACE"
	taskOpUnbind  = "UNBIND"

	maxBatchAssociate    = 10
	defaultTaskListLimit = 1000
	maxTaskListLimit     = 1000

	ecsNotFoundCode = "Ecs.0114"
)

// Resume reschedules any running KPS tasks found in the store after a restart.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("kps: resuming tasks: %w", err)
	}
	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil || scope.Kind != kindTask {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		for _, rec := range recs {
			var task Task
			if err := json.Unmarshal(rec.Data, &task); err != nil {
				return fmt.Errorf("kps: decoding %s/%s: %w", key, rec.ID, err)
			}
			if task.Status != taskStatusRunning {
				continue
			}
			s.scheduleTask(t, task)
		}
	}
	return nil
}

func (s *Service) scheduleTask(t Tenant, task Task) {
	kind := taskAssociate
	if task.Operation == taskOpUnbind {
		kind = taskDisassociate
	}
	taskID := task.ID
	s.engine.Schedule(lifecycle.Task{
		Key:  taskID,
		Kind: kind,
		Run: func(ctx context.Context, fault error) {
			s.runTask(ctx, t, taskID, fault)
		},
	})
}

func (s *Service) runTask(ctx context.Context, t Tenant, taskID string, fault error) {
	task, err := s.tasks(t).Get(ctx, taskID)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "loading kps task failed", "task_id", taskID, "error", err)
		return
	}
	if task.Status != taskStatusRunning {
		return
	}

	if fault != nil {
		s.failTask(ctx, t, taskID, errParam.Code, fault.Error())
		return
	}
	if s.servers == nil {
		s.failTask(ctx, t, taskID, "", "ECS server not found")
		return
	}

	_, exists, err := s.servers.ServerExists(ctx, t.Region, t.ProjectID, task.ServerID)
	if err != nil {
		code, msg := taskFailureReason(err)
		s.failTask(ctx, t, taskID, code, msg)
		return
	}
	if !exists {
		s.failTask(ctx, t, taskID, ecsNotFoundCode, fmt.Sprintf("The ECS %s does not exist.", task.ServerID))
		return
	}

	targetKeyName := task.KeypairName
	if task.Operation == taskOpUnbind {
		targetKeyName = ""
	}
	if err := s.servers.SetKeyName(ctx, t.Region, t.ProjectID, task.ServerID, targetKeyName); err != nil {
		code, msg := taskFailureReason(err)
		s.failTask(ctx, t, taskID, code, msg)
		return
	}

	_, err = s.tasks(t).Update(ctx, taskID, func(cur *Task) error {
		if cur.Status == taskStatusRunning {
			cur.Status = taskStatusSuccess
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "completing kps task failed", "task_id", taskID, "error", err)
	}
}

func (s *Service) failTask(ctx context.Context, t Tenant, taskID, code, msg string) {
	updated, err := s.tasks(t).Update(ctx, taskID, func(cur *Task) error {
		if cur.Status != taskStatusRunning {
			return nil
		}
		cur.Status = taskStatusFailed
		cur.ErrorCode = code
		cur.ErrorMsg = msg
		return nil
	})
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "failing kps task failed", "task_id", taskID, "error", err)
		}
		return
	}
	if updated.Status != taskStatusFailed {
		return
	}
	if err := s.failedTasks(t).Put(ctx, updated.ID, updated); err != nil {
		s.log.ErrorContext(ctx, "recording failed kps task", "task_id", taskID, "error", err)
	}
}

func taskFailureReason(err error) (code, msg string) {
	var apiErr *apierr.Error
	if errors.As(err, &apiErr) {
		return apiErr.Code, apiErr.Message
	}
	return "", err.Error()
}

func (s *Service) handleAssociateKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req associateKeypairRequest
	if err := decodeTaskBody(r, &req); err != nil {
		return err
	}
	if err := validateAssociateRequest(req); err != nil {
		return err
	}

	ctx := r.Context()
	if ok, err := s.taskKeypairVisible(ctx, t, req.KeypairName); err != nil {
		return err
	} else if !ok {
		return errBindKeypairNotExist
	}

	op := taskOpReset
	if req.Server.Auth != nil && req.Server.Auth.Type != "" {
		op = taskOpReplace
	}

	task := Task{
		ID:          s.ids.UUID(),
		Operation:   op,
		KeypairName: req.KeypairName,
		ServerID:    req.Server.ID,
		Status:      taskStatusRunning,
		CreatedAt:   s.clock().UTC().UnixMilli(),
	}
	if err := s.tasks(t).Create(ctx, task.ID, task); err != nil {
		return err
	}
	s.scheduleTask(t, task)

	return httpx.WriteJSON(w, http.StatusAccepted, taskActionResponse{
		TaskID:   task.ID,
		ServerID: req.Server.ID,
		Status:   taskStatusSuccess,
	})
}

func (s *Service) handleDisassociateKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req disassociateKeypairRequest
	if err := decodeTaskBody(r, &req); err != nil {
		return err
	}
	if req.Server == nil || req.Server.ID == "" {
		return errParam
	}
	if err := validateTaskAuth(req.Server.Auth); err != nil {
		return err
	}

	ctx := r.Context()
	task := Task{
		ID:        s.ids.UUID(),
		Operation: taskOpUnbind,
		ServerID:  req.Server.ID,
		Status:    taskStatusRunning,
		CreatedAt: s.clock().UTC().UnixMilli(),
	}
	if err := s.tasks(t).Create(ctx, task.ID, task); err != nil {
		return err
	}
	s.scheduleTask(t, task)

	return httpx.WriteJSON(w, http.StatusAccepted, taskActionResponse{
		TaskID:   task.ID,
		ServerID: req.Server.ID,
		Status:   taskStatusSuccess,
	})
}

func (s *Service) handleBatchAssociateKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req batchAssociateRequest
	if err := decodeTaskBody(r, &req); err != nil {
		return err
	}
	if len(req.BatchKeypairs) < 1 || len(req.BatchKeypairs) > maxBatchAssociate {
		return errParam
	}

	ctx := r.Context()
	results := make([]taskActionResponse, 0, len(req.BatchKeypairs))
	for _, item := range req.BatchKeypairs {
		serverID := ""
		if item.Server != nil {
			serverID = item.Server.ID
		}
		if err := validateAssociateRequest(item); err != nil {
			results = append(results, taskActionResponse{
				ServerID:  serverID,
				Status:    taskStatusFailed,
				ErrorCode: errParam.Code,
				ErrorMsg:  errParam.Message,
			})
			continue
		}
		ok, err := s.taskKeypairVisible(ctx, t, item.KeypairName)
		if err != nil {
			return err
		}
		if !ok {
			results = append(results, taskActionResponse{
				ServerID:  serverID,
				Status:    taskStatusFailed,
				ErrorCode: errBindKeypairNotExist.Code,
				ErrorMsg:  errBindKeypairNotExist.Message,
			})
			continue
		}

		op := taskOpReset
		if item.Server.Auth != nil && item.Server.Auth.Type != "" {
			op = taskOpReplace
		}
		task := Task{
			ID:          s.ids.UUID(),
			Operation:   op,
			KeypairName: item.KeypairName,
			ServerID:    serverID,
			Status:      taskStatusRunning,
			CreatedAt:   s.clock().UTC().UnixMilli(),
		}
		if err := s.tasks(t).Create(ctx, task.ID, task); err != nil {
			return err
		}
		s.scheduleTask(t, task)
		results = append(results, taskActionResponse{
			TaskID:   task.ID,
			ServerID: serverID,
			Status:   taskStatusSuccess,
		})
	}

	return httpx.WriteJSON(w, http.StatusAccepted, batchAssociateResponse{Tasks: results})
}

func (s *Service) handleListKeypairTask(w http.ResponseWriter, r *http.Request, t Tenant) error {
	taskID := chi.URLParam(r, "task_id")
	if taskID == "" {
		return errIllegalTaskID
	}
	task, err := s.tasks(t).Get(r.Context(), taskID)
	if errors.Is(err, store.ErrNotFound) {
		return errIllegalTaskID
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listKeypairTaskResponse{
		ServerID:   task.ServerID,
		TaskID:     task.ID,
		TaskStatus: wireTaskStatus(task.Operation, task.Status),
	})
}

func (s *Service) handleListRunningTask(w http.ResponseWriter, r *http.Request, t Tenant) error {
	limit, offset, err := parseTaskPagination(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	allRunning, err := s.tasks(t).List(ctx, func(task Task) bool {
		return task.Status == taskStatusRunning
	})
	if err != nil {
		return err
	}
	page := paginateTasks(allRunning, offset, limit)
	items := make([]runningTaskWire, 0, len(page))
	for _, task := range page {
		items = append(items, runningTaskWire{
			TaskID:      task.ID,
			OperateType: wireOperateType(task.Operation),
			TaskTime:    wireTaskTime(task.CreatedAt),
			ServerName:  s.lookupServerName(ctx, t, task.ServerID),
			ServerID:    task.ServerID,
			KeypairName: task.KeypairName,
		})
	}
	return httpx.WriteJSON(w, http.StatusOK, listRunningTaskResponse{
		Total: clampTaskCount(len(allRunning)),
		Tasks: items,
	})
}

func (s *Service) handleListFailedTask(w http.ResponseWriter, r *http.Request, t Tenant) error {
	limit, offset, err := parseTaskPagination(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	allFailed, err := s.failedTasks(t).List(ctx, nil)
	if err != nil {
		return err
	}
	page := paginateTasks(allFailed, offset, limit)
	items := make([]failedTaskWire, 0, len(page))
	for _, task := range page {
		var errCode *string
		if task.ErrorCode != "" {
			c := task.ErrorCode
			errCode = &c
		}
		items = append(items, failedTaskWire{
			TaskID:        task.ID,
			OperateType:   wireOperateType(task.Operation),
			TaskTime:      wireTaskTime(task.CreatedAt),
			TaskErrorCode: errCode,
			TaskErrorMsg:  task.ErrorMsg,
			ServerName:    s.lookupServerName(ctx, t, task.ServerID),
			ServerID:      task.ServerID,
			KeypairName:   task.KeypairName,
		})
	}
	return httpx.WriteJSON(w, http.StatusOK, listFailedTaskResponse{
		Total: clampTaskCount(len(allFailed)),
		Tasks: items,
	})
}

func (s *Service) handleDeleteFailedTask(w http.ResponseWriter, r *http.Request, t Tenant) error {
	taskID := chi.URLParam(r, "task_id")
	if taskID == "" {
		return errFailedTaskNotFound
	}
	err := s.failedTasks(t).Delete(r.Context(), taskID)
	if errors.Is(err, store.ErrNotFound) {
		return errFailedTaskNotFound
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleDeleteAllFailedTask(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	allFailed, err := s.failedTasks(t).List(ctx, nil)
	if err != nil {
		return err
	}
	for _, task := range allFailed {
		if err := s.failedTasks(t).Delete(ctx, task.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) taskKeypairVisible(ctx context.Context, t Tenant, name string) (bool, error) {
	kp, err := s.keypairs(t).Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return s.isVisible(ctx, kp), nil
}

func (s *Service) lookupServerName(ctx context.Context, t Tenant, serverID string) string {
	if s.servers == nil || serverID == "" {
		return ""
	}
	name, ok, err := s.servers.ServerExists(ctx, t.Region, t.ProjectID, serverID)
	if err != nil || !ok {
		return ""
	}
	return name
}

func decodeTaskBody(r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return errParam
	}
	return nil
}

func validateAssociateRequest(req associateKeypairRequest) error {
	if req.KeypairName == "" || req.Server == nil || req.Server.ID == "" {
		return errParam
	}
	if req.Server.Port != nil && (*req.Server.Port < 0 || *req.Server.Port > 65535) {
		return errParam
	}
	return validateTaskAuth(req.Server.Auth)
}

func validateTaskAuth(auth *authWire) error {
	if auth == nil || auth.Type == "" {
		return nil
	}
	if auth.Type != "password" && auth.Type != "keypair" {
		return errParam
	}
	return nil
}

func parseTaskPagination(r *http.Request) (limit, offset int, err error) {
	limit = defaultTaskListLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > maxTaskListLimit {
			return 0, 0, errParam
		}
		limit = v
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			return 0, 0, errParam
		}
		offset = v
	}
	return limit, offset, nil
}

func paginateTasks(items []Task, offset, limit int) []Task {
	if offset >= len(items) {
		return nil
	}
	return items[offset:min(offset+limit, len(items))]
}

func wireTaskStatus(op, status string) string {
	switch status {
	case taskStatusRunning:
		switch op {
		case taskOpReplace:
			return "RUNNING_REPLACE"
		case taskOpUnbind:
			return "RUNNING_UNBIND"
		default:
			return "RUNNING_RESET"
		}
	case taskStatusSuccess:
		if op == taskOpUnbind {
			return "SUCCESS_UNBIND"
		}
		return "SUCCESS_RESET"
	case taskStatusFailed:
		if op == taskOpUnbind {
			return "FAILED_UNBIND"
		}
		return "FAILED_RESET"
	default:
		return status
	}
}

func wireOperateType(op string) string {
	switch op {
	case taskOpReplace:
		return "FAILED_REPLACE"
	case taskOpUnbind:
		return "FAILED_UNBIND"
	default:
		return "FAILED_RESET"
	}
}

func wireTaskTime(createdAt int64) string {
	return strconv.FormatInt(createdAt, 10)
}

func clampTaskCount(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < 0 {
		return 0
	}
	return int32(n)
}
