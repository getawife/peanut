package proto

const (
	CmdStatus             = "status"
	CmdSetup              = "setup"
	CmdLock               = "lock"
	CmdUnlock             = "unlock"
	CmdCheck              = "check"
	CmdAppsList           = "apps_list"
	CmdAppsAdd            = "apps_add"
	CmdAppsRemove         = "apps_remove"
	CmdReset              = "reset"
	CmdForce              = "force"
	CmdAuthorizeUninstall = "authorize_uninstall"
	CmdSetQuestion        = "set_question"
	CmdCheckAnswer        = "check_answer"
	CmdUpdate             = "update"
	CmdSetAutoUpdate      = "set_auto_update"
)

const (
	CodeOK                = ""
	CodeBadPassword       = "bad_password"
	CodeCooldown          = "cooldown"
	CodeNotConfigured     = "not_configured"
	CodeAlreadyConfigured = "already_configured"
	CodeForced            = "forced"
	CodeAlreadyLocked     = "already_locked"
	CodeNotLocked         = "not_locked"
	CodeLocked            = "locked"
	CodeInvalidApp        = "invalid_app"
	CodeBlockedApp        = "blocked_app"
	CodeDuplicate         = "duplicate"
	CodeNotFound          = "not_found"
	CodeWeakPassword      = "weak_password"
	CodeEmptyName         = "empty_name"
	CodeStorage           = "storage"
	CodeForceStarted      = "force_started"
	CodeForceWaiting      = "force_waiting"
	CodeUnknownCommand    = "unknown_command"
	CodeBadAnswer         = "bad_answer"
	CodeWeakAnswer        = "weak_answer"
	CodeEmptyQuestion     = "empty_question"
	CodeNoQuestion        = "no_question"
	CodeUpToDate          = "up_to_date"
	CodeUpdateReady       = "update_ready"
	CodeUpdating          = "updating"
	CodeUpdateFailed      = "update_failed"
	CodeUpdatesDisabled   = "updates_disabled"
)

type App struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type Request struct {
	Cmd         string `json:"cmd"`
	Name        string `json:"name,omitempty"`
	Password    string `json:"password,omitempty"`
	NewPassword string `json:"new_password,omitempty"`
	Question    string `json:"question,omitempty"`
	Answer      string `json:"answer,omitempty"`
	Enable      bool   `json:"enable,omitempty"`
	App         *App   `json:"app,omitempty"`
}

type Status struct {
	Configured   bool   `json:"configured"`
	Name         string `json:"name"`
	Locked       bool   `json:"locked"`
	Forced       bool   `json:"forced"`
	Apps         int    `json:"apps"`
	HasQuestion  bool   `json:"has_question"`
	Question     string `json:"question,omitempty"`
	Version      string `json:"version,omitempty"`
	AutoUpdate   bool   `json:"auto_update"`
	GraceLeft    int    `json:"grace_left"`
	ForceLeft    int    `json:"force_left"`
	CooldownLeft int    `json:"cooldown_left"`
	AttemptsLeft int    `json:"attempts_left"`
}

type Response struct {
	OK     bool    `json:"ok"`
	Code   string  `json:"code,omitempty"`
	Wait   int     `json:"wait,omitempty"`
	Text   string  `json:"text,omitempty"`
	Status *Status `json:"status,omitempty"`
	Apps   []App   `json:"apps,omitempty"`
}