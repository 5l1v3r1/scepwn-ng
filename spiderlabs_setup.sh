#!/bin/bash

# Setup script for scepwn-ng for SpiderLabs default virtual machine

sed -i '' "s/WINEXE = .*/WINEXE = \"\/pentest\/SpiderLabs\/winexe-PTH\"/" scepwn-ng.rb
sed -i '' "s/SCE = .*/SCE = \"\/pentest\/SpiderLabs\/Win-Tools\/sce.32.exe\"/" scepwn-ng.rb

