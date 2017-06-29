package main

func BLE(done <-chan struct{}, auth Authenticator, storage CredentialStorage) <-chan error {
	status := make(chan error)
	close(status)
	return status
}
