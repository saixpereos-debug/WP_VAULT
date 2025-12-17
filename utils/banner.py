#!/usr/bin/env python3

import sys
import os
import math

# ASCII Art for Vṛthā (Vrtha)
# Font: Standard/Slant
BANNER = r"""
__     __      _   _          
\ \   / /_ __ | |_| |__   __ _ 
 \ \ / /| '__|| __| '_ \ / _` |
  \ V / | |   | |_| | | | (_| |
   \_/  |_|    \__|_| |_|\__,_|
                               
      Advanced WordPress VA Tool
"""

def saffron_text(text):
    output = ""
    # Saffron (Kesari) Color
    # Approx RGB: 255, 153, 51
    r, g, b = 255, 153, 51
    
    lines = text.splitlines()
    for line in lines:
        for char in line:
            # ANSI escape sequence for TrueColor
            output += f"\033[38;2;{r};{g};{b}m{char}"
        output += "\033[0m\n" # Reset
    return output

def main():
    print("\n")
    print(saffron_text(BANNER))
    print("\033[38;2;200;200;200m             v2.0 - Created by Sai\033[0m\n")

if __name__ == "__main__":
    main()
