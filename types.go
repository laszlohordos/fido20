package main

type (
	PublicKeyCredentialEntity struct {
		Id   string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
		Name string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
	}
	PublicKeyCredentialUserEntity struct {
		Id          string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
		Name        string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
		DisplayName string `protobuf:"bytes,3,opt,name=displayName" json:"displayName,omitempty"`
	}
)
