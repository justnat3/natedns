#!/bin/bash

go run -C cmd/resolver . &
sleep 1;
go run -C cmd/lookup_tester .
