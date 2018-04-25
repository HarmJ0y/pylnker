pylnker
=======
This is a fork of pylnker aimed to turn the original code into a class. The output that would normally be printed has
been added to a dictionary which is returned to you after using the parse() function.

Credits:
- Original CLI tool: https://github.com/HarmJ0y/pylnker
- Pylinker was ported from: https://code.google.com/p/revealertoolkit/source/browse/trunk/tools/lnk-parse-1.0.pl  
  - Jacob Cunningham - jakec76@users.sourceforge.net
- Which is originally based on: https://ithreats.files.wordpress.com/2009/05/lnk_the_windows_shortcut_file_format.pdf
  - Jesse Hager - hessehager@iname.com


Usage:
```python
from pylnker import Pylnker
 
data = Pylnker("path_to_lnk").parse()
```
