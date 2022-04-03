package objects

import "time"

// swagger:model ThingResponse
type ThingResponse struct {
	// The UUID of a thing
	// example: 6204037c-30e6-408b-8aaa-dd8219860b4b
	UUID string `json:"uuid"`

	// The Name of a thing
	// example: Some name
	Name string `json:"name"`

	// The Value of a thing
	// example: Some value
	Value string `json:"value"`

	// The last time a thing was updated
	// example: 2021-05-25T00:53:16.535668Z
	Updated time.Time `json:"updated"`

	// The time a thing was created
	// example: 2021-05-25T00:53:16.535668Z
	Created time.Time `json:"created"`
}


// HTTPClientError returned when a client error occurs
type HTTPClientError struct {
	Code    int    `json:"code" example:"400"`
	Message string `json:"message" example:"status bad request"`
}

// HTTPServerError returned when a server error occurs
type HTTPServerError struct {
	Code    int    `json:"code" example:"502"`
	Message string `json:"message" example:"status server error"`
}
