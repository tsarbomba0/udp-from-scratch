package util

func OnError(err error) {
	if err != nil {
		panic(err)
	}
}
