#!/bin/bash
bash -c "
sudo apt purge -y \
  *game* \
  minetest* \
  supertux* \
  0ad* \
  frozen-bubble \
  gnome-games \
  aisleriot \
  gnome-mahjongg \
  gnome-mines \
  gnome-sudoku \
  endless-sky \
  zangband \
  angband \
  nethack* \
  2>/dev/null
  
  sudo apt autoremove -y
"
