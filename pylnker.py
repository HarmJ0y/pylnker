# Copyright (C) 2017 KillerInstinct
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import binascii
import datetime
import logging
import mmap

from struct import unpack

logging.basicConfig()
log = logging.getLogger(__name__)


class Pylnker(object):
    # HASH of flag attributes
    flag_hash = [[_, 1] for _ in xrange(27)]
    flag_hash[0][1] = "HasLinkTargetIDList"
    flag_hash[1][1] = "HasLinkInfo"
    flag_hash[2][1] = "HasName"
    flag_hash[3][1] = "HasRelativePath"
    flag_hash[4][1] = "HasWorkingDir"
    flag_hash[5][1] = "HasArguments"
    flag_hash[6][1] = "HasIconLocation"
    flag_hash[7][1] = "IsUnicode"
    flag_hash[8][1] = "ForceNoLinkInfo"
    flag_hash[9][1] = "HasExpString"
    flag_hash[10][1] = "RunInSeparateProcess"
    flag_hash[11][1] = "Unused1"
    flag_hash[12][1] = "HasDarwinID"
    flag_hash[13][1] = "RunAsUser"
    flag_hash[14][1] = "HasExpIcon"
    flag_hash[15][1] = "NoPidlAlias"
    flag_hash[16][1] = "Unused2"
    flag_hash[17][1] = "RunWithShimLayer"
    flag_hash[18][1] = "ForceNoLinkTrack"
    flag_hash[19][1] = "EnableTargetMetadata"
    flag_hash[20][1] = "DisableLinkPathTracking"
    flag_hash[21][1] = "DisableKnownFolderTracking"
    flag_hash[22][1] = "DisableKnownFolderAlias"
    flag_hash[23][1] = "AllowLinkToLink"
    flag_hash[24][1] = "UnaliasOnSave"
    flag_hash[25][1] = "PreferEnvironmentPath"
    flag_hash[26][1] = "KeepLocalIDListForUNCTarget"

    # HASH of FileAttributes
    file_hash = [[_, 1] for _ in xrange(17)]
    file_hash[0][1] = "FILE_ATTRIBUTE_READONLY"
    file_hash[1][1] = "FILE_ATTRIBUTE_HIDDEN"
    file_hash[2][1] = "FILE_ATTRIBUTE_SYSTEM"
    file_hash[3][1] = "VOLUME LABEL TARGET (not possible)"
    file_hash[4][1] = "FILE_ATTRIBUTE_DIRECTORY"
    file_hash[5][1] = "FILE_ATTRIBUTE_ARCHIVE"
    file_hash[6][1] = "NTFS EFS (not possible)"
    file_hash[7][1] = "FILE_ATTRIBUTE_NORMAL"
    file_hash[8][1] = "FILE_ATTRIBUTE_TEMPORARY"
    file_hash[9][1] = "FILE_ATTRIBUTE_SPARSE_FILE"
    file_hash[10][1] = "FILE_ATTRIBUTE_REPARSE_POINT"
    file_hash[11][1] = "FILE_ATTRIBUTE_COMPRESSED"
    file_hash[12][1] = "FILE_ATTRIBUTE_OFFLINE"
    file_hash[13][1] = "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"
    file_hash[14][1] = "FILE_ATTRIBUTE_ENCRYPTED"
    file_hash[15][1] = "Unknown (seen on Windows 95 fat)"
    file_hash[16][1] = "FILE_ATTRIBUTE_VIRTUAL (reserved for future use)"

    # Hash of ShowWnd values
    show_wnd_hash = [_ for _ in xrange(11)]
    show_wnd_hash[0] = "SW_HIDE"
    show_wnd_hash[1] = "SW_NORMAL"
    show_wnd_hash[2] = "SW_SHOWMINIMIZED"
    show_wnd_hash[3] = "SW_SHOWMAXIMIZED"
    show_wnd_hash[4] = "SW_SHOWNOACTIVE"
    show_wnd_hash[5] = "SW_SHOW"
    show_wnd_hash[6] = "SW_MINIMIZE"
    show_wnd_hash[7] = "SW_SHOWMINNOACTIVE"
    show_wnd_hash[8] = "SW_SHOWNA"
    show_wnd_hash[9] = "SW_RESTORE"
    show_wnd_hash[10] = "SW_SHOWDEFAULT"

    # Hash for Volume types
    drive_type_hash = [_ for _ in xrange(7)]
    drive_type_hash[0] = "Unknown"
    drive_type_hash[1] = "No root directory"
    drive_type_hash[2] = "Removable (Floppy,Zip,USB,etc.)"
    drive_type_hash[3] = "Fixed (Hard Disk)"
    drive_type_hash[4] = "Remote (Network Drive)"
    drive_type_hash[5] = "CD-ROM"
    drive_type_hash[6] = "RAM Drive"

    # Hash of LinkInfo flags
    link_info_flags_hash = [[_, 1] for _ in xrange(2)]
    link_info_flags_hash[0][1] = "VolumeIDAndLocalBasePath"
    link_info_flags_hash[1][1] = "CommonNetworkRelativeLinkAndPathSuffix"

    # Has of Network Relative Link Flags
    nrl_flags_hash = [[_, 1] for _ in xrange(2)]
    nrl_flags_hash[0][1] = "ValidDevice"
    nrl_flags_hash[1][1] = "ValidNetType"

    # HASH of HotKeyFlags
    hot_key_value = {
        0: "None",
        48: "0",
        49: "1",
        50: "2",
        51: "3",
        52: "4",
        53: "5",
        54: "6",
        55: "7",
        56: "8",
        57: "9",
        65: "A",
        66: "B",
        67: "C",
        68: "D",
        69: "E",
        70: "F",
        71: "G",
        72: "H",
        73: "I",
        74: "J",
        75: "K",
        76: "L",
        77: "M",
        78: "N",
        79: "O",
        80: "P",
        81: "Q",
        82: "R",
        83: "S",
        84: "T",
        85: "U",
        86: "V",
        87: "W",
        88: "X",
        89: "Y",
        99: "Z",
        112: "F1",
        113: "F2",
        114: "F3",
        115: "F4",
        116: "F5",
        117: "F6",
        118: "F7",
        119: "F8",
        120: "F9",
        121: "F10",
        122: "F11",
        123: "F12",
    }
    known_folder_name = {
        "DE61D971-5EBC-4F02-A3A9-6C82895E5C04": "AddNewPrograms",
        "724EF170-A42D-4FEF-9F26-B60E846FBA4F": "AdminTools",
        "A520A1A4-1780-4FF6-BD18-167343C5AF16": "AppDataLow",
        "A305CE99-F527-492B-8B1A-7E76FA98D6E4": "AppUpdates",
        "9E52AB10-F80D-49DF-ACB8-4330F5687855": "CDBurning",
        "DF7266AC-9274-4867-8D55-3BD661DE872D": "ChangeRemovePrograms",
        "D0384E7D-BAC3-4797-8F14-CBA229B392B5": "CommonAdminTools",
        "C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D": "CommonOEMLinks",
        "0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8": "CommonPrograms",
        "A4115719-D62E-491D-AA7C-E74B8BE3B067": "CommonStartMenu",
        "82A5EA35-D9CD-47C5-9629-E15D2F714E6E": "CommonStartup",
        "B94237E7-57AC-4347-9151-B08C6C32D1F7": "CommonTemplates",
        "0AC0837C-BBF8-452A-850D-79D08E667CA7": "Computer",
        "4BFEFB45-347D-4006-A5BE-AC0CB0567192": "Conflict",
        "6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD": "Connections",
        "56784854-C6CB-462B-8169-88E350ACB882": "Contacts",
        "82A74AEB-AEB4-465C-A014-D097EE346D63": "ControlPanel",
        "2B0F765D-C0E9-4171-908E-08A611B84FF6": "Cookies",
        "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Desktop",
        "FDD39AD0-238F-46AF-ADB4-6C85480369C7": "Documents",
        "374DE290-123F-4565-9164-39C4925E467B": "Downloads",
        "1777F761-68AD-4D8A-87BD-30B759FA33DD": "Favorites",
        "FD228CB7-AE11-4AE3-864C-16F3910AB8FE": "Fonts",
        "CAC52C1A-B53D-4EDC-92D7-6B2E8AC19434": "Games",
        "054FAE61-4DD8-4787-80B6-090220C4B700": "GameTasks",
        "D9DC8A3B-B784-432E-A781-5A1130A75963": "History",
        "4D9F7874-4E0C-4904-967B-40B0D20C3E4B": "Internet",
        "352481E8-33BE-4251-BA85-6007CAEDCF9D": "InternetCache",
        "BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968": "Links",
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": "LocalAppData",
        "2A00375E-224C-49DE-B8D1-440DF7EF3DDC": "LocalizedResourcesDir",
        "4BD8D571-6D19-48D3-BE97-422220080E43": "Music",
        "C5ABBF53-E17F-4121-8900-86626FC2C973": "NetHood",
        "D20BEEC4-5CA8-4905-AE3B-BF251EA09B53": "Network",
        "2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39": "OriginalImages",
        "69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C": "PhotoAlbums",
        "33E28130-4E1E-4676-835A-98395C3BC3BB": "Pictures",
        "DE92C1C7-837F-4F69-A3BB-86E631204A23": "Playlists",
        "76FC4E2D-D6AD-4519-A663-37BD56068185": "Printers",
        "9274BD8D-CFD1-41C3-B35E-B13F55A758F4": "PrintHood",
        "5E6C858F-0E22-4760-9AFE-EA3317B67173": "Profile",
        "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97": "ProgramData",
        "905E63B6-C1BF-494E-B29C-65B732D3D21A": "ProgramFiles",
        "F7F1ED05-9F6D-47A2-AAAE-29D317C6F066": "ProgramFilesCommon",
        "6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D": "ProgramFilesCommonX64",
        "DE974D24-D9C6-4D3E-BF91-F4455120B917": "ProgramFilesCommonX86",
        "6D809377-6AF0-444B-8957-A3773F02200E": "ProgramFilesX64",
        "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": "ProgramFilesX86",
        "A77F5D77-2E2B-44C3-A6A2-ABA601054A51": "Programs",
        "DFDF76A2-C82A-4D63-906A-5644AC457385": "Public",
        "C4AA340D-F20F-4863-AFEF-F87EF2E6BA25": "PublicDesktop",
        "ED4824AF-DCE4-45A8-81E2-FC7965083634": "PublicDocuments",
        "3D644C9B-1FB8-4F30-9B45-F670235F79C0": "PublicDownloads",
        "DEBF2536-E1A8-4C59-B6A2-414586476AEA": "PublicGameTasks",
        "3214FAB5-9757-4298-BB61-92A9DEAA44FF": "PublicMusic",
        "B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5": "PublicPictures",
        "2400183A-6185-49FB-A2D8-4A392A602BA3": "PublicVideos",
        "52A4F021-7B75-48A9-9F6B-4B87A210BC8F": "QuickLaunch",
        "AE50C081-EBD2-438A-8655-8A092E34987A": "Recent",
        "BD85E001-112E-431E-983B-7B15AC09FFF1": "RecordedTV",
        "B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC": "RecycleBin",
        "8AD10C31-2ADB-4296-A8F7-E4701232C972": "ResourceDir",
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": "RoamingAppData",
        "B250C668-F57D-4EE1-A63C-290EE7D1AA1F": "SampleMusic",
        "C4900540-2379-4C75-844B-64E6FAF8716B": "SamplePictures",
        "15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5": "SamplePlaylists",
        "859EAD94-2E85-48AD-A71A-0969CB56A6CD": "SampleVideos",
        "4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4": "SavedGames",
        "7D1D3A04-DEBB-4115-95CF-2F29DA2920DA": "SavedSearches",
        "EE32E446-31CA-4ABA-814F-A5EBD2FD6D5E": "SEARCH_CSC",
        "98EC0E18-2098-4D44-8644-66979315A281": "SEARCH_MAPI",
        "190337D1-B8CA-4121-A639-6D472D16972A": "SearchHome",
        "8983036C-27C0-404B-8F08-102D10DCFD74": "SendTo",
        "7B396E54-9EC5-4300-BE0A-2482EBAE1A26": "SidebarDefaultParts",
        "A75D362E-50FC-4FB7-AC2C-A8BEAA314493": "SidebarParts",
        "625B53C3-AB48-4EC1-BA1F-A1EF4146FC19": "StartMenu",
        "B97D20BB-F46A-4C97-BA10-5E3608430854": "Startup",
        "43668BF8-C14E-49B2-97C9-747784D784B7": "SyncManager",
        "289A9A43-BE44-4057-A41B-587A76D7E7F9": "SyncResults",
        "0F214138-B1D3-4A90-BBA9-27CBC0C5389A": "SyncSetup",
        "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": "System",
        "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27": "SystemX86",
        "A63293E8-664E-48DB-A079-DF759E0509F7": "Templates",
        "5B3749AD-B49F-49C1-83EB-15370FBD4882": "TreeProperties",
        "0762D272-C50A-4BB0-A382-697DCD729B80": "UserProfiles",
        "F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F": "UsersFiles",
        "18989B1D-99B5-455B-841C-AB7C74E4DDFC": "Videos",
        "F38BF404-1D43-42F2-9305-67DE0B28FC23": "Windows",
    }

    def __init__(self, lnk_path):
        self.path = lnk_path
        self.lnk_obj = None
        self.end_offset = 0
        self.data = {
            "Link_Flags": [],
            "File_Attributes": [],
            "Create_Time": "Not Set",
            "Access_Time": "Not Set",
            "Write_Time": "Not Set",
            "File_Size": "",
            "Icon_Index": "",
            "Show_Command": "",
            "Hot_Key": "",
            "Target": {},
            "Link_Info": {},
            "String_Data": {
                "Name_String": "",
                "Relative_Path": "",
                "Working_Directory": "",
                "Command_Line_Arguments": "",
                "Icon_Location": "",
            },
            "Extra_Data": {}
        }

    # Helper functions to resolve  hot keys/known folders
    def hot_key_hash(self, hot_key):
        return self.hot_key_value.get(hot_key, "Unknown")

    def known_folder_name_hash(self, folder):
        return self.known_folder_name.get(folder, "Unknown")

    # Helper functions for operating on the lnk_obj in the class
    def lnk_open(self):
        self.lnk_obj = open(self.path, "rb")

    def lnk_close(self):
        self.lnk_obj.close()

    def get_block_size_from_signature_offset(self, offset):
        self.lnk_obj.seek(offset - 4)
        return unpack("i", self.lnk_obj.read(4))[0]

    def set_end_offset(self, offset):
        # end_offset = x bytes of data (length 'x' of the next segment) - offset length (DWORD)
        end_offset = self.get_block_size_from_signature_offset(offset) - 4 + offset
        if end_offset > self.end_offset:
            self.end_offset = end_offset

    @staticmethod
    def reverse_hex(hex_str):
        hex_vals = [hex_str[i:i + 2] for i in xrange(0, 16, 2)]
        reverse_hex_vals = hex_vals[::-1]
        return ''.join(reverse_hex_vals)

    @staticmethod
    def ms_time_to_unix(windows_time):
        unix_time = windows_time / 10000000.0 - 11644473600
        return datetime.datetime.utcfromtimestamp(unix_time).strftime("%Y-%m-%d %H:%M:%S.%f")

    def assert_lnk_signature(self):
        self.lnk_obj.seek(0)
        sig = self.lnk_obj.read(4)
        if sig != 'L\x00\x00\x00':
            log.error("This is not a .lnk file.")
            return False

        guid = self.lnk_obj.read(16)
        if guid != '\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F':
            log.error("Cannot read this kind of .lnk file.")
            return False

        return True

    # read COUNT bytes at LOC and unpack into ascii
    def read_unpack_ascii(self, loc, count):
        self.lnk_obj.seek(loc)
        return unpack("{}s".format(count), self.lnk_obj.read(count))[0].replace("\x00", "")

    # read COUNT bytes at LOC and unpack into binary
    def read_unpack_bin(self, loc, count):
        self.lnk_obj.seek(loc)
        raw = self.lnk_obj.read(count)
        result = ""
        for b in raw:
            result += ("{0:08b}".format(ord(b)))[::-1]

        return result

    # read COUNT bytes at LOC
    def read_unpack(self, loc, count):
        self.lnk_obj.seek(loc)
        return binascii.hexlify(self.lnk_obj.read(count))

    # Read a null terminated string from the specified location.
    def read_null_term(self, loc):
        self.lnk_obj.seek(loc)
        b = self.lnk_obj.read(1)

        result = ""
        while b != "\x00":
            result += str(b)
            b = self.lnk_obj.read(1)

        return result

    def add_info(self, loc):
        """
        Parses a WORD (CountCharacters) which then gives us a length to parse. Double this length to account for
        Unicode data
        :param loc: Index in the file to seek to
        :return: a tuple with the string, and the current file index
        """
        self.lnk_obj.seek(loc)
        count_characters = unpack("h", self.lnk_obj.read(2))[0]
        length = count_characters * 2
        if length != 0:
            tmp_string = unpack("{}s".format(length), self.lnk_obj.read(length))[0].replace("\x00", "")
            now_loc = self.lnk_obj.tell()
            return tmp_string, now_loc
        else:
            now_loc = self.lnk_obj.tell()
            return "", now_loc

    @staticmethod
    def split_count(s, count):
        return ':'.join(s[i:i + count] for i in range(0, len(s), count))

    def structure(self, struct_end, v):
        # get the number of items
        if v == "t":
            items_hex = self.reverse_hex(self.read_unpack(struct_end, 2))
            items = int(items_hex, 16)
            list_end = struct_end + 2 + items
        else:
            items_hex = self.reverse_hex(self.read_unpack(struct_end, 4))
            items = int(items_hex, 16)
            list_end = struct_end + 0 + items

        struct_end = list_end

        return struct_end

    def parse_shell_link_header(self):
        # get the flag bits
        flags = self.read_unpack_bin(20, 4)

        # flags are only the first 7 bits not
        for cnt in xrange(len(flags) - 5):
            bit = int(flags[cnt])
            # grab the description for this bit
            if isinstance(self.flag_hash[cnt][bit], str):
                self.data["Link_Flags"].append(self.flag_hash[cnt][bit])

        # File Attributes 4bytes@18h = 24d
        # Only a non-zero if "Flag bit 1" above is set to 1
        if flags[1] == "1":
            file_attrib = self.read_unpack_bin(24, 2)
            self.data["File_Attributes"] = self.file_hash[file_attrib.index("1")][1]

        # Create time 8bytes @ 1ch = 28
        creation_time = int(self.reverse_hex(self.read_unpack(28, 8)), 16)
        if creation_time != 0:
            self.data["Create_Time"] = self.ms_time_to_unix(creation_time)

        # Access time 8 bytes@ 0x24 = 36D
        access_time = int(self.reverse_hex(self.read_unpack(36, 8)), 16)
        if access_time != 0:
            self.data["Access_Time"] = self.ms_time_to_unix(access_time)

        # Modified Time 8bytes @ 0x2C = 44D
        write_time = int(self.reverse_hex(self.read_unpack(44, 8)), 16)
        if creation_time != 0:
            self.data["Write_Time"] = self.ms_time_to_unix(write_time)

        # Target File length starts @ 34h = 52d
        length_hex = self.reverse_hex(self.read_unpack(52, 4))
        self.data["File_Size"] = int(length_hex, 16)

        # Icon File info starts @ 38h = 56d
        icon_index_hex = self.reverse_hex(self.read_unpack(56, 4))
        self.data["Icon_Index"] = int(icon_index_hex, 16)

        # show windows starts @3Ch = 60d
        show_command_hex = self.reverse_hex(self.read_unpack(60, 1))
        show_command = int(show_command_hex, 16)
        self.data["Show_Command"] = self.show_wnd_hash[show_command]

        # hot key starts @40h = 64d
        hotkey_hex = self.reverse_hex(self.read_unpack(64, 4))
        hotkey = int(hotkey_hex, 16)
        get_hotkey = self.hot_key_hash(hotkey)
        if get_hotkey:
            self.data["Hot_Key"] = get_hotkey
        else:
            log.warn("Unknown hot key: %s" % str(hotkey))

        return flags

    def parse_link_target_id_list(self, struct_end):
        struct_end = self.structure(struct_end, v="t")
        return struct_end

    def parse_link_info(self, struct_end):
        lnk_info = {}
        struct_start = struct_end
        # struct_end = self.structure(struct_end, v="i")

        link_info_header_size = struct_start + 4
        link_info_flags = struct_start + 8
        volume_id_off = struct_start + 12
        local_base_path_off = struct_start + 16
        common_network_relative_link_off = struct_start + 20
        common_path_suffix_off = struct_start + 24

        # Structure length
        struct_len_hex = self.reverse_hex(self.read_unpack(struct_start, 4))
        struct_len = int(struct_len_hex, 16)
        struct_end = struct_start + struct_len

        # First offset after struct - Should be 1C under normal circumstances
        header_size = self.read_unpack(link_info_header_size, 1)
        lnk_info["Link_Info_Header_Size"] = str(int(header_size, 16))

        if lnk_info["Link_Info_Header_Size"] >= "36":
            # local_base_path_off_unicode = struct_start + 28
            # common_path_suffix_off_unicode = struct_start + 32
            log.info("Link Info Header Size > 35 bytes. Report this file if possible.")

        # File location flags
        link_info_flags = self.read_unpack_bin(link_info_flags, 1)
        lnk_info["Link_Info_Flags"] = self.link_info_flags_hash[link_info_flags.index("1")][1]

        lnk_info["Target_Location"] = "Not Set"
        # VolumeID structure
        # Random garbage if bit0 is clear in volume flags
        if link_info_flags[0] == "1":
            lnk_info["Target_Location"] = "Local"

            # This is the offset of the local volume table within the
            # File Info Location Structure
            loc_vol_tab_off_hex = self.reverse_hex(self.read_unpack(volume_id_off, 4))
            loc_vol_tab_off = int(loc_vol_tab_off_hex, 16)

            # This is the absolute start location of the local volume table
            loc_vol_tab_start = loc_vol_tab_off + struct_start

            # This is the length of the local volume table
            local_vol_len_hex = self.reverse_hex(self.read_unpack(loc_vol_tab_off + struct_start, 4))
            local_vol_len = int(local_vol_len_hex, 16)

            # We now have enough info to
            # Calculate the end of the local volume table.
            local_vol_tab_end = loc_vol_tab_start + local_vol_len

            # This is the volume type
            drive_type_flag = loc_vol_tab_off + struct_start + 4
            drive_type_hex = self.reverse_hex(self.read_unpack(drive_type_flag, 4))
            drive_type = int(drive_type_hex, 16)
            lnk_info["Drive_Type"] = self.drive_type_hash[drive_type]

            # Volume Serial Number
            drive_serial_number = loc_vol_tab_off + struct_start + 8
            drive_serial_number = self.reverse_hex(self.read_unpack(drive_serial_number, 4))
            lnk_info["Drive_Serial_Number"] = drive_serial_number

            # Get the location, and length of the volume label
            # need to add check for VolumeLabelOffsetUnicode
            # Kind of messy. Works for now.
            vol_label_off = loc_vol_tab_off + struct_start + 12
            vol_label_off_hex = self.reverse_hex(self.read_unpack(vol_label_off, 4))[6:]
            lnk_info["Volume_Label_Offset"] = vol_label_off_hex
            vol_label_start = int(vol_label_off_hex, 16) + loc_vol_tab_start
            vol_label_len = local_vol_tab_end - vol_label_start
            vol_label = self.read_unpack_ascii(vol_label_start, vol_label_len)
            lnk_info["Volume_Label"] = vol_label

            # ---------------------------------------------------------------------
            # This is the offset of the base path info within the
            # File Info structure
            # ---------------------------------------------------------------------

            base_path_off_hex = self.reverse_hex(self.read_unpack(local_base_path_off, 4))
            local_base_path_off = struct_start + int(base_path_off_hex, 16)

            # Read base path data up to NULL term
            base_path = self.read_null_term(local_base_path_off)
            lnk_info["Base_Path"] = base_path

        # Network Volume Table
        if link_info_flags[1] == "1":
            # TODO: test this section!
            lnk_info["Target_Location"] = "Network"

            net_vol_off_hex = self.reverse_hex(self.read_unpack(common_network_relative_link_off, 4))
            common_network_relative_link_off = struct_start + int(net_vol_off_hex, 16)
            # net_vol_len_hex = reverse_hex(read_unpack(f, common_network_relative_link_off, 4))
            # net_vol_len = struct_start + int(net_vol_len_hex, 16)

            # CommonNetworkRelativeLinkFlags
            network_relative_link_flags_loc = common_network_relative_link_off + 4
            network_relative_link_flags = self.read_unpack_bin(network_relative_link_flags_loc, 4)

            lnk_info["Network_Relative_Link_Flags"] = []
            for cnt in xrange(len(network_relative_link_flags) - 30):
                bit = int(network_relative_link_flags[cnt])
                # grab the description for this bit
                if self.nrl_flags_hash[cnt][bit]:
                    lnk_info["Network_Relative_Link_Flags"].append(self.nrl_flags_hash[cnt][bit])

            # Network Share Name
            net_share_name_off = common_network_relative_link_off + 8
            net_share_name_loc_hex = self.reverse_hex(self.read_unpack(net_share_name_off, 4))
            net_share_name_loc = int(net_share_name_loc_hex, 16)

            if net_share_name_loc == 20:
                net_share_name_loc += common_network_relative_link_off
                net_share_name = self.read_null_term(net_share_name_loc)
                lnk_info["Network_Share_Name"] = net_share_name

                # Mapped Network Drive Info
                net_share_mdrive = common_network_relative_link_off + 12
                net_share_mdrive_hex = self.reverse_hex(self.read_unpack(net_share_mdrive, 4))
                net_share_mdrive = int(net_share_mdrive_hex, 16)

                if net_share_mdrive != 0:
                    net_share_mdrive += common_network_relative_link_off
                    mapped_drive = self.read_null_term(net_share_mdrive)
                    lnk_info['mapped_drive'] = mapped_drive
            else:
                log.error("Net Share Name offset should always be 14h")

        else:
            log.warn("Unknown volume flags")

        # Remaining path
        rem_path_off_hex = self.reverse_hex(self.read_unpack(common_path_suffix_off, 4))
        common_path_suffix_off = struct_start + int(rem_path_off_hex, 16)
        rem_data = self.read_null_term(common_path_suffix_off)
        lnk_info["Remaining_Path"] = rem_data
        self.data["Link_Info"] = lnk_info

        return struct_end

    def parse_string_data(self, flags, struct_end):
        next_loc = struct_end
        if flags[2] == "1":
            text, next_loc = self.add_info(next_loc)
            if text != "0":
                self.data["String_Data"]["Name_String"] = text

        if flags[3] == "1":
            text, next_loc = self.add_info(next_loc)
            if text != "0":
                self.data["String_Data"]["Relative_Path"] = text

        if flags[4] == "1":
            text, next_loc = self.add_info(next_loc)
            if text != "0":
                self.data["String_Data"]["Working_Directory"] = text

        if flags[5] == "1":
            text, next_loc = self.add_info(next_loc)
            if text != "0":
                self.data["String_Data"]["Command_Line_Arguments"] = text

        if flags[6] == "1":
            text, next_loc = self.add_info(next_loc)
            if text != "0":
                self.data["String_Data"]["Icon_Location"] = text

        return struct_end

    def parse_console_data_block(self, offset):
        cdb = {}
        # fill_attributes_loc = offset + 4
        # popup_fill_attributes_loc = offset + 6

        screen_buffer_size_x_loc = offset + 8
        screen_buffer_size_x_hex = self.reverse_hex(self.read_unpack(screen_buffer_size_x_loc, 2))
        screen_buffer_size_x = int(screen_buffer_size_x_hex, 16)
        cdb["Screen_Buffer_Size_X"] = screen_buffer_size_x

        screen_buffer_size_y_loc = offset + 10
        screen_buffer_size_y_hex = self.reverse_hex(self.read_unpack(screen_buffer_size_y_loc, 2))
        screen_buffer_size_y = int(screen_buffer_size_y_hex, 16)
        cdb["Screen_Buffer_Size_Y"] = screen_buffer_size_y

        window_size_x_loc = offset + 12
        window_size_x_hex = self.reverse_hex(self.read_unpack(window_size_x_loc, 2))
        window_size_x = int(window_size_x_hex, 16)
        cdb["Window_Size_X"] = window_size_x

        window_size_y_loc = offset + 14
        window_size_y_hex = self.reverse_hex(self.read_unpack(window_size_y_loc, 2))
        window_size_y = int(window_size_y_hex, 16)
        cdb["Window_Size_Y"] = window_size_y

        window_origin_x_loc = offset + 16
        window_origin_x_hex = self.reverse_hex(self.read_unpack(window_origin_x_loc, 2))
        window_origin_x = int(window_origin_x_hex, 16)
        cdb["Window_Origin_X"] = window_origin_x

        window_origin_y_loc = offset + 18
        window_origin_y_hex = self.reverse_hex(self.read_unpack(window_origin_y_loc, 2))
        window_origin_y = int(window_origin_y_hex, 16)
        cdb["Window_Origin_Y"] = window_origin_y

        font_size_loc = offset + 28
        font_size_hex = self.read_unpack(font_size_loc, 4)
        font_size_hex = [self.reverse_hex(font_size_hex[0:4]), self.reverse_hex(font_size_hex[4:8])]
        font_size_hex = ''.join(font_size_hex)
        font_size = int(font_size_hex, 16)
        cdb["Font_Size"] = font_size

        # font_family_loc = offset + 32

        font_weight_loc = offset + 36
        font_weight_hex = self.reverse_hex(self.read_unpack(font_weight_loc, 4))
        font_weight = int(font_weight_hex, 16)
        is_bold = font_weight >= 700
        cdb["Is_Bold"] = is_bold

        # face_name_loc = offset + 40

        cursor_size_loc = offset + 104
        cursor_size_hex = self.reverse_hex(self.read_unpack(cursor_size_loc, 4))
        cursor_size = int(cursor_size_hex, 16)
        if cursor_size <= 25:
            cdb["Cursor_Size"] = "Small"

        elif 25 < cursor_size <= 50:
            cdb["Cursor_Size"] = "Normal"

        elif 50 < cursor_size <= 100:
            cdb["Cursor_Size"] = "Large"

        full_screen_loc = offset + 108
        full_screen_hex = self.reverse_hex(self.read_unpack(full_screen_loc, 4))
        full_screen = int(full_screen_hex, 16)
        is_full_screen = full_screen > 0
        cdb["Is_Full_Screen"] = is_full_screen

        quick_edit_loc = offset + 112
        quick_edit_hex = self.reverse_hex(self.read_unpack(quick_edit_loc, 4))
        quick_edit = int(quick_edit_hex, 16)
        is_quick_edit = quick_edit > 0
        cdb["Is_Quick_Edit"] = is_quick_edit

        insert_mode_loc = offset + 116
        insert_mode_hex = self.reverse_hex(self.read_unpack(insert_mode_loc, 4))
        insert_mode = int(insert_mode_hex, 16)
        is_insert_mode = insert_mode > 0
        cdb["Is_Insert_Mode"] = is_insert_mode

        auto_position_loc = offset + 120
        auto_position_hex = self.reverse_hex(self.read_unpack(auto_position_loc, 4))
        auto_position = int(auto_position_hex, 16)
        is_auto_position = auto_position > 0
        cdb["Is_Auto_Position"] = is_auto_position

        history_buffer_size_loc = offset + 124
        history_buffer_size_hex = self.reverse_hex(self.read_unpack(history_buffer_size_loc, 4))
        history_buffer_size = int(history_buffer_size_hex, 16)
        cdb["History_Buffer_Size"] = history_buffer_size

        history_buffer_count_loc = offset + 128
        history_buffer_count_hex = self.reverse_hex(self.read_unpack(history_buffer_count_loc, 4))
        history_buffer_count = int(history_buffer_count_hex, 16)
        cdb["History_Buffer_Count"] = history_buffer_count

        history_nodup_loc = offset + 132
        history_nodup_hex = self.reverse_hex(self.read_unpack(history_nodup_loc, 4))
        history_nodup = int(history_nodup_hex, 16)
        is_history_nodup = history_nodup > 0
        cdb["Is_History_Nodup"] = is_history_nodup

        self.data["Extra_Data"]["Console_Data_Block"] = cdb
        self.set_end_offset(offset)

    def parse_console_fe_data_block(self, offset):
        self.data["Extra_Data"]["Console_FE_Data_Block"] = {}
        self.set_end_offset(offset)

    def parse_darwin_data_block(self, offset):
        self.data["Extra_Data"]["Darwin_Data_Block"] = {}
        self.set_end_offset(offset)

    def parse_environment_variable_data_block(self, offset):
        evdb = {}
        target_ansi_loc = offset + 4
        # target_unicode_loc = offset + 264  # not complete
        target_ansi = self.read_null_term(target_ansi_loc)
        evdb["Target"] = target_ansi
        self.data["Extra_Data"]["Environment_Variable_Data_Block"] = evdb
        self.set_end_offset(offset)

    def parse_icon_environment_data_block(self, offset):
        iedb = {}
        target_ansi_loc = offset + 4
        # target_unicode_loc = offset + 264  # not complete
        target_ansi = self.read_null_term(target_ansi_loc)
        iedb["Target"] = target_ansi
        self.data["Extra_Data"]["Icon_Environment_Data_Block"] = iedb
        self.set_end_offset(offset)

    def parse_known_folder_data_block(self, offset):
        kfdb = {}
        known_folder_data_block_loc = offset + 4
        known_folder_id = self.read_unpack(known_folder_data_block_loc, 16)
        fields = [self.reverse_hex(known_folder_id[0:8]), self.reverse_hex(known_folder_id[8:12]),
                  self.reverse_hex(known_folder_id[12:16]), known_folder_id[16:20], known_folder_id[20:32]]
        known_folder_guid = '-'.join(fields)
        known_folder_name = self.known_folder_name_hash(known_folder_guid)
        kfdb["Known_Folder_Name"] = known_folder_name
        kfdb["Known_Folder_GUID"] = known_folder_guid
        self.data["Extra_Data"]["Known_Folder_Data_Block"] = kfdb
        self.set_end_offset(offset)

    def parse_property_store_data_block(self, offset):
        self.data["Extra_Data"]["Property_Store_Data_Block"] = {}
        self.set_end_offset(offset)

    def parse_shim_data_block(self, offset):
        self.data["Extra_Data"]["Shim_Data_Block"] = {}
        self.set_end_offset(offset)

    def parse_special_folder_data_block(self, offset):
        sfdb = {}
        special_folder_id_loc = offset + 4
        special_folder_id_hex = self.reverse_hex(self.read_unpack(special_folder_id_loc, 4))
        special_folder_id = int(special_folder_id_hex, 16)
        sfdb["Special_Folder_Id"] = special_folder_id
        self.data["Extra_Data"]["Special_Folder_Data_Block"] = sfdb
        self.set_end_offset(offset)

    def parse_tracker_data_block(self, offset):
        tdb = {}
        # MachineID
        machine_id_loc = offset + 12
        machine_id = self.read_null_term(machine_id_loc)
        tdb["Machine_Id"] = machine_id

        # NewObjectID MAC Address
        mac_address_loc = offset + 54
        mac_address = self.split_count(self.read_unpack(mac_address_loc, 6), 2)
        tdb["Mac_Address"] = mac_address

        # Volume Droid
        volume_droid_loc = offset + 28
        volume_droid = self.read_unpack(volume_droid_loc, 16)
        fields = [self.reverse_hex(volume_droid[0:8]), self.reverse_hex(volume_droid[8:12]),
                  self.reverse_hex(volume_droid[12:16]), volume_droid[16:20], volume_droid[20:32]]
        volume_droid = '-'.join(fields)
        tdb["Volume_Droid"] = volume_droid

        # Volume Droid Birth
        # volume_droid_birth_loc = offset + 60
        volume_droid_birth = self.read_unpack(volume_droid_loc, 16)
        fields = [self.reverse_hex(volume_droid_birth[0:8]), self.reverse_hex(volume_droid_birth[8:12]),
                  self.reverse_hex(volume_droid_birth[12:16]), volume_droid_birth[16:20], volume_droid_birth[20:32]]
        volume_droid_birth = '-'.join(fields)
        tdb["Volume_Droid_Birth"] = volume_droid_birth

        # File Droid
        file_droid_loc = offset + 44
        file_droid = self.read_unpack(file_droid_loc, 16)
        fields = [self.reverse_hex(file_droid[0:8]), self.reverse_hex(file_droid[8:12]),
                  self.reverse_hex(file_droid[12:16]), file_droid[16:20], file_droid[20:32]]
        file_droid = '-'.join(fields)
        tdb["File_Droid"] = file_droid

        # Creation time
        file_droid_time = ''.join(fields)
        timestamp = int((file_droid_time[13:16] + file_droid_time[8:12] + file_droid_time[0:8]), 16)
        creation = datetime.datetime.utcfromtimestamp((timestamp - 0x01b21dd213814000L) * 100 / 1e9)
        tdb["Creation"] = creation.strftime("%Y-%m-%d %H:%M:%S.%f")

        # File Droid Birth
        file_droid_birth_loc = offset + 76
        file_droid_birth = self.read_unpack(file_droid_birth_loc, 16)
        fields = [self.reverse_hex(file_droid_birth[0:8]), self.reverse_hex(file_droid_birth[8:12]),
                  self.reverse_hex(file_droid_birth[12:16]), file_droid_birth[16:20], file_droid_birth[20:32]]
        file_droid_birth = '-'.join(fields)
        tdb["File_Droid_Birth"] = file_droid_birth
        self.data["Extra_Data"]["Tracker_Data_Block"] = tdb
        self.set_end_offset(offset)

    def parse_vista_and_above_id_list_data_block(self, offset):
        self.data["Extra_Data"]["Vista_And_Above_Id_List_data_Block"] = {}
        self.set_end_offset(offset)

    def parse_extra_data(self):
        # Map the file
        haystack = mmap.mmap(self.lnk_obj.fileno(), length=0, access=mmap.ACCESS_READ)

        # Find ExtraDataBlock's using their signatures documented by
        # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK]-131114.pdf
        # Sections 2.5.x (BlockSignature)
        console_data_block_offset = haystack.find("\x02\x00\x00\xA0")
        console_fe_data_block_offset = haystack.find("\x04\x00\x00\xA0")
        darwin_data_block_offset = haystack.find("\x06\x00\x00\xA0")
        environment_variable_data_block_offset = haystack.find("\x01\x00\x00\xA0")
        icon_environment_data_block_offset = haystack.find("\x07\x00\x00\xA0")
        known_folder_data_block_offset = haystack.find("\x0B\x00\x00\xA0")
        property_store_data_block_offset = haystack.find("\x09\x00\x00\xA0")
        shim_data_block_offset = haystack.find("\x08\x00\x00\xA0")
        special_folder_data_block_offset = haystack.find("\x05\x00\x00\xA0")
        tracker_data_block_offset = haystack.find("\x03\x00\x00\xA0")
        vista_and_above_id_list_data_block_offset = haystack.find("\x0C\x00\x00\xA0")

        if console_data_block_offset > 0:
            log.info("Found ConsoleDataBlock signature, report this hash if possible.")
            self.parse_console_data_block(console_data_block_offset)

        if console_fe_data_block_offset > 0:
            log.info("Found ConsoleFEDataBlock, report this hash if possible.")
            self.parse_console_fe_data_block(console_fe_data_block_offset)

        if darwin_data_block_offset > 0:
            log.info("Found DarwinDataBlock, report this hash if possible.")
            self.parse_darwin_data_block(darwin_data_block_offset)

        if environment_variable_data_block_offset > 0:
            log.info("Found EnvironmentVariableDataBlock, report this hash if possible")
            self.parse_environment_variable_data_block(environment_variable_data_block_offset)

        if icon_environment_data_block_offset > 0:
            log.info("Found IconEnvironmentDataBlock, report this hash if possible")
            self.parse_icon_environment_data_block(icon_environment_data_block_offset)

        if known_folder_data_block_offset > 0:
            self.parse_known_folder_data_block(known_folder_data_block_offset)

        if property_store_data_block_offset > 0:
            log.info("Found PropertyStoryDataBlock, report this hash if possible")
            self.parse_property_store_data_block(property_store_data_block_offset)

        if shim_data_block_offset > 0:
            log.info("Found ShimDataBlock, report this hash if possible")
            self.parse_shim_data_block(shim_data_block_offset)

        if special_folder_data_block_offset > 0:
            self.parse_special_folder_data_block(special_folder_data_block_offset)

        if tracker_data_block_offset > 0:
            self.parse_tracker_data_block(tracker_data_block_offset)

        if vista_and_above_id_list_data_block_offset > 0:
            log.info("Found VistaAndAboveIDListDataBlock, report this hash if possible")
            self.parse_vista_and_above_id_list_data_block(vista_and_above_id_list_data_block_offset)

        haystack.close()

    def parse(self):
        self.lnk_open()
        if not self.assert_lnk_signature():
            self.lnk_close()
            return {}

        struct_end = 76
        flags = self.parse_shell_link_header()
        if "HasLinkTargetIDList" in self.data["Link_Flags"]:
            struct_end = self.parse_link_target_id_list(struct_end)

        if "HasLinkInfo" in self.data["Link_Flags"]:
            struct_end = self.parse_link_info(struct_end)

        string_flags = ["HasName", "HasRelativePath", "HasWorkingDir", "HasArguments", "HasIconLocation"]
        if any(x in self.data["Link_Flags"] for x in string_flags):
            self.parse_string_data(flags, struct_end)

        self.parse_extra_data()

        # Verify the end of the lnk, check for extra data
        self.lnk_obj.seek(self.end_offset)
        end_block = unpack("4s", self.lnk_obj.read(4))[0]
        if end_block == "\x00\x00\x00\x00":
            self.end_offset += 4
            self.lnk_obj.seek(0, 2)
            file_end = self.lnk_obj.tell()
            # Check for data after the terminating block, grab it out if there is any
            if file_end > self.end_offset:
                self.lnk_obj.seek(self.end_offset)
                data_size = file_end - self.end_offset
                self.data["Data_After_EOF"] = {
                    "Size": data_size,
                    "Data": self.lnk_obj.read(data_size)
                }
        else:
            log.error("Parsing did not find the lnk terminating block properly")

        self.lnk_close()

        return self.data
