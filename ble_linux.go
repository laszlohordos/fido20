package main

import (
	"github.com/paypal/gatt"
	"time"
)

func BLE(done <-chan struct{}, auth Authenticator, storage CredentialStorage) <-chan error {
	status := make(chan error, 1)
	go func() {
		//Start BLE Service
		d, err := gatt.NewDevice(DefaultServerOptions...)
		if err != nil {
			logger.Error("Failed to open device", "error", err)
			status <- err
		} else {
			defer func() {
				logger.Info("Stopping FIDO20 Authenticator")
				d.StopAdvertising()
				d.RemoveAllServices()
				centralStore.RLock()
				defer centralStore.RUnlock()

				for _, e := range centralStore.m {
					e.Central.Close()
				}
			}()

			// Register optional handlers.
			d.Handle(
				gatt.CentralConnected(func(c gatt.Central) {
					logger.Info("Connect", "central", c.ID())
					centralStore.Lock()
					defer centralStore.Unlock()

					entry := &StoreEntry{
						Central:  c,
						Receiver: make(chan *Request, 1),
					}
					entry.Receiver <- &Request{}
					centralStore.m[c.ID()] = entry

				}),
				gatt.CentralDisconnected(func(c gatt.Central) {
					logger.Info("Disconnect", "central", c.ID())
					centralStore.Lock()
					defer centralStore.Unlock()
					delete(centralStore.m, c.ID())
				}),
			)

			// A mandatory handler for monitoring device state.
			err = d.Init(func(d gatt.Device, s gatt.State) {
				switch s {
				case gatt.StateUnknown:
					logger.Info("StateChanged", "status", "StateUnknown")
				case gatt.StateResetting:
					logger.Info("StateChanged", "status", "StateResetting")
				case gatt.StateUnsupported:
					logger.Info("StateChanged", "status", "StateUnsupported")
				case gatt.StateUnauthorized:
					logger.Info("StateChanged", "status", "StateUnauthorized")
				case gatt.StatePoweredOff:
					logger.Info("StateChanged", "status", "StatePoweredOff")
				case gatt.StatePoweredOn:
					logger.Info("StateChanged", "status", "StatePoweredOn")
					// Setup GAP and GATT services for Linux implementation.
					// OS X doesn't export the access of these services.
					//d.AddService(service.NewGapService("Gopher")) // no effect on OS X
					//d.AddService(service.NewGattService())        // no effect on OS X

					// A simple count service for demo.
					//s1 := gattservice.NewConfigurationService()
					s1 := NewFIDO11Service(done, auth, storage)
					d.AddService(s1)

					// Add a simple counter service.
					s2 := NewBatteryService()
					d.AddService(s2)

					s3 := NewUserDataService()
					d.AddService(s3)

					// Setup GAP and GATT services.
					d.AddService(NewGapService("FIDO20"))
					d.AddService(NewGattService())

					// A fake battery service for demo.
					//s2 := service.NewBatteryService()
					//d.AddService(s2)

					// Advertise device name and service's UUIDs.
					d.AdvertiseNameAndServices("FIDO20", []gatt.UUID{s1.UUID(), s2.UUID(), s3.UUID()})

					// Advertise as an OpenBeacon iBeacon
					//d.AdvertiseIBeacon(gatt.MustParseUUID("AA6062F098CA42118EC4193EB73CCEB6"), 1, 2, -59)

					select {
					case status <- nil:
					case <-time.After(250 * time.Millisecond):
					}
				default:
				}
			})
			if err != nil {
				logger.Error("Failed to Init device", "error", err)
				status <- err
			} else {
				logger.Info("Start FIDO20 Authenticator")
				<-done
			}
		}
	}()
	return status
}
