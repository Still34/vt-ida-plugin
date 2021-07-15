# VT-IDA Plugin
This is the official VirusTotal plugin for Hex-Rays IDA Pro. This plugin integrates functionality from VirusTotal web services into the IDA Pro's user interface. 

The current version is v1.0beta, This plugin is not production-ready yet, and unexpected behavior can still occur. This release integrates VTGrep into IDA Pro, facilitating the searching for similar code, strings, or sequences of bytes. It also adds an additional panel to the IDA Pro interface (View -> Open subviews -> VirusTotal) to show information extracted from VirusTotal that could help during the reversing process.

## Requirements
This plugin has been developed for **IDA Pro 7** (>= 7.4) and Python 3. 
It requires the "requests" and "vt-py" modules, the easiest way of installing them is by using the ``pip`` command:

```bash
$ pip install requests vt-py
```
or 

```bash
$ python -m pip install requests vt-py
```


## Installation
Copy the content of the ``plugin`` directory into the IDA Pro's plugin directory and start IDA Pro. 

| OS      | Plugin path                                 |
| ------- | ------------------------------------------- |
| Linux   | `/opt/ida-7.X/plugins`                      |
| macOS   | `~/.idapro/plugins`                         |
| Windows | `%ProgramFiles%\IDA 7.X\plugins`       |


## Usage

### Searching for similar content
While in the disassembly window, select an area of a set of instructions and right-click to chose one of the following actions:

- *Search for bytes*: it searches for the bytes contained in the selected area.
- *Search for string*: it searches for the same string as the one selected in the Strings Window.
- *Search for similar code*: identifies memory offsets or addresses in the currently selected area and ignores them when searching.
- *Search for similar code (strict)*: same as above but it also ignores all the constants in the currently selected area.
- *Search for similar functions*: same as "similar code" but you don’t need to select all the instructions that belong to a function. Just right-click on one instruction, and it will automatically detect the function boundaries, selecting all the instructions of the current function.

Another option is to look for similar strings. To search for similar ones, open the `Strings Windows` in IDA Pro, right-click on any string (one or many) and select `Virus Total -> Search for string`. 

These actions will launch a new instance of your default web browser, showing all the matches found in VTGrep. Remember that your default web browser must be logged into your VirusTotal Enterprise account in order to see the results.

**Note**: This version supports **Intel 32/64 bits** and **ARM** processor architectures when searching for similar code. Probably more architectures are supported but it hasn't been tested yet.

### Navigate through VTPanel
TBA

Check IDA Pro's output window for any message that may need your attention.
