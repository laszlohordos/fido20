# Package fido20 provides a Bluetooth Low Energy GATT Fido 2.0 implementation.

Sample code for [FIDO 2.0 WebAuth (Draft):](https://w3c.github.io/webauthn/) authenticator.

## SETUP

### Fido 2.0 BLE supports Linux only not OS X.

### On Linux:
To gain complete and exclusive control of the HCI device, gatt uses
HCI_CHANNEL_USER (introduced in Linux v3.14) instead of HCI_CHANNEL_RAW.
Those who must use an older kernel may patch in these relevant commits
from Marcel Holtmann:

    Bluetooth: Introduce new HCI socket channel for user operation
    Bluetooth: Introduce user channel flag for HCI devices
    Bluetooth: Refactor raw socket filter into more readable code

Note that because gatt uses HCI_CHANNEL_USER, once gatt has opened the
device no other program may access it.

Before starting a gatt program, make sure that your BLE device is down:

    sudo hciconfig
    sudo hciconfig hci0 down  # or whatever hci device you want to use

If you have BlueZ 5.14+ (or aren't sure), stop the built-in
bluetooth server, which interferes with gatt, e.g.:

    sudo service bluetooth stop

Because gatt programs administer network devices, they must
either be run as root, or be granted appropriate capabilities:

    sudo <executable>
    # OR
    sudo setcap 'cap_net_raw,cap_net_admin=eip' <executable>
    <executable>

## Usage

    go get github.com/laszlohordos/fido20
    make
    sudo ./fido20

## Testing

Use the [nRF Connect for mobile](https://www.nordicsemi.com/eng/Products/Nordic-mobile-Apps/nRF-Connect-for-mobile-previously-called-nRF-Master-Control-Panel) program for testing.
Connect to **FIDO20** device and open service **FFFD** and follow the [FIDO 2.0: Client To Authenticator Protocol](https://fidoalliance.org/specs/fido-v2.0-rd-20161004/fido-client-to-authenticator-protocol-v2.0-rd-20161004.html#bluetooth-smart-bluetooth-low-energy-ble).


GetInfo Frame[0]=

    83000104

MakeCredential Frame[0]=

    8300f101a70583a263616c6765502d323536626f706b67656e65726174654b6579a263616c6765502d333834626f706b67656e65726174654b6579a2626f706b67656e65726174654b657963616c6765502d35323107a263747570f56474657374647465737408f4016452504944025820000000000000000000000000000000000000000000000000000000000000000003a2626964781968747470733a2f2f666f726765726f636b6c6162732e636f6d646e616d6569466f726765526f636b04a3646e616d65676c686f72646f736b646973706c61794e616d656d4c61737a6c6f20486f72646f73626964676c686f72646f73

GetAssertion Frame[0]=

    83005202a304a263747570f56474657374647465737401781968747470733a2f2f666f726765726f636b6c6162732e636f6d0258200000000000000000000000000000000000000000000000000000000000000000
