#!/bin/bash
cd poxdesk
curl -L http://downloads.sourceforge.net/qooxdoo/qooxdoo-2.0.2-sdk.zip > qooxdoo-2.0.2-sdk.zip
unzip qooxdoo-2.0.2-sdk.zip
mv qooxdoo-2.0.2-sdk qx
rm qooxdoo-2.0.2-sdk.zip
cd poxdesk 
./generate.py
cd ../..
