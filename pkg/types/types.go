package types

type EventResponse struct {
	Status   string `json:"status"`
	Id       string `json:"id"`
	From     string `json:"from"`
	Type     string
	Action   string
	Actor    EventActor
	Time     int64 `json:"time"`
	TimeNano int64 `json:"timeNano"`
}

type EventActor struct {
	ID         string
	Attributes *map[string]string
}
