#!/bin/bash

getent group sudo | cut -d: -f4 | tr ',' '\n'