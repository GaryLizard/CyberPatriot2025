#!/bin/bash


sudo apt purge *game* 
sudo apt purge minetest* 
sudo apt purge supertux* 
sudo apt purge 0ad* 
sudo apt purge frozen-bubble 
sudo apt purge gnome-games 
sudo apt purge aisleriot 
sudo apt purge gnome-mahjongg 
sudo apt purge gnome-mines 
sudo apt purge gnome-sudoku 
sudo apt purge endless-sky 
sudo apt purge zangband 
sudo apt purge angband 
sudo apt purge nethack* 
sudo snap remove --purge duckmarines
sudo snap remove --purge obs-studio

sudo apt autoremove -y
