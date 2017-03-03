// +build linux

/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2016 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/intelsdi-x/snap-plugin-collector-snmp/collector/configReader"
	"github.com/intelsdi-x/snap/core/serror"
	"github.com/k-sone/snmpgo"
)

func NewHandler(agentConfig configReader.SnmpAgent) (*snmpgo.SNMP, serror.SnapError) {
	handler, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:          getSNMPVersion(agentConfig.SnmpVersion),
		Network:          agentConfig.Network,
		Address:          agentConfig.Address,
		Timeout:          time.Duration(agentConfig.Timeout) * time.Second,
		Retries:          agentConfig.Retries,
		Community:        agentConfig.Community,
		UserName:         agentConfig.UserName,
		SecurityLevel:    getSNMPSecurityLevel(agentConfig.SecurityLevel),
		AuthPassword:     agentConfig.AuthPassword,
		AuthProtocol:     getSNMPAuthProtocol(agentConfig.AuthProtocol),
		PrivPassword:     agentConfig.PrivPassword,
		PrivProtocol:     getPrivProtocol(agentConfig.PrivProtocol),
		SecurityEngineId: agentConfig.SecurityEngineId,
		ContextEngineId:  agentConfig.ContextEngineId,
		ContextName:      agentConfig.ContextName,
	})

	if err != nil {
		return nil, serror.New(err)
	}
	return handler, nil
}

func ReadElements(handler *snmpgo.SNMP, oid string, mode string) ([]*snmpgo.VarBind, serror.SnapError) {
	fmt.Println("* ReadElements oid*", oid, "*")
	//results received through SNMP requests
	results := []*snmpgo.VarBind{}

	if err := handler.Open(); err != nil {
		// Failed to open connection
		return results, serror.New(err)
	}

	//get elements in node OID
	nodeOid := strings.Trim(oid, ".")

	oidParts := strings.Split(nodeOid, ".")

	//get length of node OID (used to stop reading in table and walk modes)
	nodeOIDLength := len(oidParts)
	fmt.Println("* nodeOid: *", nodeOid ," ", " oidParts: ", oidParts, " nodeOIDLength: ", nodeOIDLength, " *")
	//previous OID (used to stop reading in table and walk modes)
	var prevOid string

	//loop through one node of MIB
	for {
		oids, err := snmpgo.NewOids([]string{oid})
		if err != nil {
			// Failed to parse Oids
			fmt.Println("snmpgo.NewOids error: ", err, "*")
			return results, serror.New(err)
		}
		fmt.Println("* oids: ", oids, "*")

		var pdu snmpgo.Pdu
		if mode == configReader.ModeSingle {
			pdu, err = handler.GetRequest(oids)
			fmt.Println("* handler.GetRequest pdu: ", pdu, "*", time.Now().Second())
		} else {
			pdu, err = handler.GetNextRequest(oids)
			fmt.Println("* handler.GetNextRequest pdu: ", pdu, "*", time.Now().Second())
		}
		if err != nil {
			// Failed to request
			fmt.Println(" Get error: ", err)
			return results, serror.New(err)
		}

		if pdu.ErrorStatus() != snmpgo.NoError {
			// Received an error from the agent
			fmt.Println("* Status: ", pdu.ErrorStatus(), "*")
			return results, serror.New(fmt.Errorf("Received an error from the SNMP agent: %v", pdu.ErrorStatus()))
		}

		if len(pdu.VarBinds()) != 1 {
			fmt.Println("* Unaccepted number of results *")
			return results, serror.New(fmt.Errorf("Unaccepted number of results, received %v results", len(pdu.VarBinds())))
		}

		// select a VarBind
		result := pdu.VarBinds()[0]
		fmt.Println("* result: ", result, " *", time.Now().Second())

		if mode == configReader.ModeSingle {
			results = append(results, result)
			fmt.Println("* single mode resutls : ", results, " *")
			break
		} else {
			oid = result.Oid.String()

			//get current elements in node OID
			currOidParts := strings.Split(strings.Trim(oid, "."), ".")
			fmt.Println("*walk mode oid : ", oid, " currOidParts: ", currOidParts," *")

			// if length of new oid is lower then it is the another node
			if len(currOidParts) < nodeOIDLength {
				fmt.Println("walk mode break len(currOidParts)", len(currOidParts), " currOidParts ", currOidParts, " *")
				break
			}

			currNodeOid := strings.Join(currOidParts[:nodeOIDLength], ".")

			fmt.Println("walk mode currNodeOid:",currNodeOid , "*")

			fmt.Println("* walk mode *")
			fmt.Println("nodeOid:", nodeOid, " *")
			fmt.Println("currNodeOid:", currNodeOid, " *")
			fmt.Println("prevOid:", prevOid, " *")
			fmt.Println("oid:", oid, " *")
			fmt.Println("mode:", mode, " *")
			fmt.Println("len(oidParts)+1):", len(oidParts)+1, " *")
			fmt.Println("len(currOidParts):", len(currOidParts), " *")
			//check if there is a new element to read
			if nodeOid != currNodeOid || prevOid == oid ||
				(mode == configReader.ModeTable && (len(oidParts)+1) != len(currOidParts)) {

				fmt.Println("* walk mode break 2 *")
				break
			}
			prevOid = oid
			fmt.Println("* walk mode results: ", result, "*")
			results = append(results, result)
		}
	}
	return results, nil
}

func getSNMPVersion(s string) snmpgo.SNMPVersion {
	var snmpVersion snmpgo.SNMPVersion
	switch s {
	case "v1":
		snmpVersion = snmpgo.V1
	case "v2c":
		snmpVersion = snmpgo.V2c
	case "v3":
		snmpVersion = snmpgo.V3
	}
	return snmpVersion
}

func getSNMPSecurityLevel(s string) snmpgo.SecurityLevel {
	var securitylevel snmpgo.SecurityLevel
	switch s {
	case "NoAuthNoPriv":
		securitylevel = snmpgo.NoAuthNoPriv
	case "AuthNoPriv":
		securitylevel = snmpgo.AuthNoPriv
	case "AuthPriv":
		securitylevel = snmpgo.AuthPriv
	}
	return securitylevel
}
func getSNMPAuthProtocol(s string) snmpgo.AuthProtocol {
	var authProtocol snmpgo.AuthProtocol
	switch s {
	case "MD5":
		authProtocol = snmpgo.Md5
	case "SHA":
		authProtocol = snmpgo.Sha
	}
	return authProtocol
}

func getPrivProtocol(s string) snmpgo.PrivProtocol {
	var privProtocol snmpgo.PrivProtocol
	switch s {
	case "DES":
		privProtocol = snmpgo.Des
	case "AES":
		privProtocol = snmpgo.Aes
	}
	return privProtocol
}
