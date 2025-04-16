package response

type Response struct {
	Status string `json:"status"`
	Error  string `json:"response"`
}

const (
	StatusError = "Error"
)

func Error(msg string) Response {
	return Response{
		Status: StatusError,
		Error:  msg,
	}
}
