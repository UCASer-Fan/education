#!/bin/bash +x
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


#set -e

CHANNEL_NAME=$1
: ${CHANNEL_NAME:="kevinkongyixueyuan"}
echo $CHANNEL_NAME

export FABRIC_CFG_PATH=$PWD
echo

## remove crypto-config and configtx
function removeAll() {
    if [ -d "./crypto-config" ]; then
        rm -rf ./crypto-config
    fi

    if [ -d "./artifacts" ]; then
        rm -rf ./artifacts
    fi
}


## Replace example to kevin.kongyixueyuan in coypto-config.yaml & configtx.yaml
function replaceName() {
    OS_ARCH=$(echo "$(uname -s|tr '[:upper:]' '[:lower:]'|sed 's/mingw64_nt.*/windows/')-$(uname -m | sed 's/x86_64/amd64/g')" | awk '{print tolower($0)}')

	ARCH=`uname -s | grep Darwin`
	if [ "$ARCH" == "Darwin" ]; then
		OPTS="-it"
	else
		OPTS="-i"
	fi

    sed $OPTS "s/example/kevin.kongyixueyuan/g" crypto-config.yaml
    sed $OPTS "s/example/kevin.kongyixueyuan/g" configtx.yaml
}


## Generates Org certs using cryptogen tool
function generateCerts (){
	CRYPTOGEN=$FABRIC_CFG_PATH/cryptogen

	if [ -f "$CRYPTOGEN" ]; then
            echo "Using cryptogen -> $CRYPTOGEN"
	else
	    echo "No cryptogen"
	fi

	echo
	echo "##########################################################"
	echo "##### Generate certificates using cryptogen tool #########"
	echo "##########################################################"
	$CRYPTOGEN generate --config=./crypto-config.yaml
	echo
}



## Generate orderer genesis block , channel configuration transaction and anchor peer update transactions
function generateChannelArtifacts() {

	CONFIGTXGEN=$FABRIC_CFG_PATH/configtxgen
	if [ -f "$CONFIGTXGEN" ]; then
            echo "Using configtxgen -> $CONFIGTXGEN"
	else
	    echo "No configtxgen"
	fi

    mkdir -p ./artifacts

	echo "##########################################################"
	echo "#########  Generating Orderer Genesis block ##############"
	echo "##########################################################"
	# Note: For some unknown reason (at least for now) the block file can't be
	# named orderer.genesis.block or the orderer will fail to launch!
	$CONFIGTXGEN -profile OneOrgOrdererGenesis -outputBlock ./artifacts/genesis.block
	#$CONFIGTXGEN -profile OneOrgOrdererGenesis -channelID kevinkongyixueyuan -outputBlock ./artifacts/genesis.block

	echo
	echo "#################################################################"
	echo "### Generating channel configuration transaction 'channel.tx' ###"
	echo "#################################################################"
	$CONFIGTXGEN -profile OneOrgChannel -outputCreateChannelTx ./artifacts/channel.tx -channelID $CHANNEL_NAME

	echo
	echo "#################################################################"
	echo "#######    Generating anchor peer update for Org1MSP   ##########"
	echo "#################################################################"
	#$CONFIGTXGEN -profile OneOrgChannel -outputAnchorPeersUpdate ./artifacts/Org1MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org1MSP
    $CONFIGTXGEN -profile OneOrgChannel -outputAnchorPeersUpdate ./artifacts/Org1MSPanchors.tx -channelID $CHANNEL_NAME -asOrg KongyixueyuanOrg

	echo
	echo "#################################################################"
	echo "# Generating json file for Genesis block, Channel tx and Anchor peer tx #"
	echo "#################################################################"
	$CONFIGTXGEN -inspectBlock artifacts/genesis.block > artifacts/genesis.block.json
	$CONFIGTXGEN -inspectChannelCreateTx artifacts/channel.tx > artifacts/channel.tx.json
    $CONFIGTXGEN -inspectChannelCreateTx artifacts/Org1MSPanchors.tx > artifacts/Org1MSPanchor.tx.json

}

removeAll
replaceName
generateCerts
generateChannelArtifacts
