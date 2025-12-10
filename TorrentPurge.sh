#!/bin/bash
bash -c "
sudo apt purge -y \
  transmission* \
  deluge* \
  qbittorrent* \
  vuze \
  frostwire \
  *torrent* \
  amule \
  emule \
  2>/dev/null
sudo apt autoremove -y
"
