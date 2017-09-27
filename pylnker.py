import binascii
import datetime
import logging

logging.basicConfig()
log = logging.getLogger(__name__)


class Pylnker(object):
    # HASH of flag attributes
    flag_hash = [["", ""] for _ in xrange(7)]
    flag_hash[0][1] = "HAS SHELLIDLIST"
    flag_hash[0][0] = "NO SHELLIDLIST"
    flag_hash[1][1] = "POINTS TO FILE/DIR"
    flag_hash[1][0] = "NOT POINT TO FILE/DIR"
    flag_hash[2][1] = "HAS DESCRIPTION"
    flag_hash[2][0] = "NO DESCRIPTION"
    flag_hash[3][1] = "HAS RELATIVE PATH STRING"
    flag_hash[3][0] = "NO RELATIVE PATH STRING"
    flag_hash[4][1] = "HAS WORKING DIRECTORY"
    flag_hash[4][0] = "NO WORKING DIRECTORY"
    flag_hash[5][1] = "HAS CMD LINE ARGS"
    flag_hash[5][0] = "NO CMD LINE ARGS"
    flag_hash[6][1] = "HAS CUSTOM ICON"
    flag_hash[6][0] = "NO CUSTOM ICON"

    # HASH of FileAttributes
    file_hash = [["", ""] for _ in xrange(15)]
    file_hash[0][1] = "READ ONLY"
    file_hash[1][1] = "HIDDEN"
    file_hash[2][1] = "SYSTEM FILE"
    file_hash[3][1] = "VOLUME LABEL (not possible)"
    file_hash[4][1] = "DIRECTORY"
    file_hash[5][1] = "ARCHIVE"
    file_hash[6][1] = "NTFS EFS"
    file_hash[7][1] = "NORMAL"
    file_hash[8][1] = "TEMP"
    file_hash[9][1] = "SPARSE"
    file_hash[10][1] = "REPARSE POINT DATA"
    file_hash[11][1] = "COMPRESSED"
    file_hash[12][1] = "OFFLINE"
    file_hash[13][1] = "NOT_CONTENT_INDEXED"
    file_hash[14][1] = "ENCRYPTED"

    # Hash of ShowWnd values
    show_wnd_hash = [[""] for _ in xrange(11)]
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
    vol_type_hash = [[""] for _ in xrange(7)]
    vol_type_hash[0] = "Unknown"
    vol_type_hash[1] = "No root directory"
    vol_type_hash[2] = "Removable (Floppy,Zip,USB,etc.)"
    vol_type_hash[3] = "Fixed (Hard Disk)"
    vol_type_hash[4] = "Remote (Network Drive)"
    vol_type_hash[5] = "CD-ROM"
    vol_type_hash[6] = "RAM Drive"

    def __init__(self, lnk_path):
        self.path = lnk_path
        self.lnk_obj = None
        self.data = {
            "Link_Flags": [],
            "File_Attributes": [],
            "Create_Time": "",
            "Access_Time": "",
            "Modified_Time": "",
            "Length": "",
            "Icon_Index": "",
            "Show_Window": "",
            "Hot_Key": "",
            "Target": {},
            "Parsed_Flags": {},
        }

    def lnk_open(self):
        self.lnk_obj = open(self.path, "rb")

    def lnk_close(self):
        self.lnk_obj.close()

    @staticmethod
    def reverse_hex(hex_str):
        hex_vals = [hex_str[i:i + 2] for i in xrange(0, 16, 2)]
        reverse_hex_vals = hex_vals[::-1]
        return ''.join(reverse_hex_vals)

    # adapted from pylink.py
    @staticmethod
    def ms_time_to_unix_str(windows_time):
        time_str = ''
        try:
            unix_time = windows_time / 10000000.0 - 11644473600
            time_str = str(datetime.datetime.fromtimestamp(unix_time))
        except:
            pass
        return time_str

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
        # jump to the specified location
        self.lnk_obj.seek(loc)

        # should interpret as ascii automagically
        return self.lnk_obj.read(count)

    # read COUNT bytes at LOC and unpack into binary
    def read_unpack_bin(self, loc, count):
        # jump to the specified location
        self.lnk_obj.seek(loc)
        raw = self.lnk_obj.read(count)
        result = ""
        for b in raw:
            result += ("{0:08b}".format(ord(b)))[::-1]

        return result

    # read COUNT bytes at LOC
    def read_unpack(self, loc, count):
        # jump to the specified location
        self.lnk_obj.seek(loc)
        raw = self.lnk_obj.read(count)

        result = ""
        for b in raw:
            result += binascii.hexlify(b)

        return result

    # Read a null terminated string from the specified location.
    def read_null_term(self, loc):
        # jump to the start position
        self.lnk_obj.seek(loc)
        b = self.lnk_obj.read(1)

        result = ""
        while b != "\x00":
            result += str(b)
            b = self.lnk_obj.read(1)

        return result

    def add_info(self, loc):
        tmp_len_hex = self.reverse_hex(self.read_unpack(loc, 2))
        tmp_len = 2 * int(tmp_len_hex, 16)
        loc += 2

        if tmp_len != 0:
            tmp_string = self.read_unpack_ascii(loc, tmp_len)
            now_loc = self.lnk_obj.tell()
            return tmp_string, now_loc
        else:
            now_loc = self.lnk_obj.tell()
            return None, now_loc

    def parse(self):
        self.lnk_open()
        if not self.assert_lnk_signature():
            self.lnk_close()
            return {}

        # get the flag bits
        flags = self.read_unpack_bin(20, 1)

        # flags are only the first 7 bits
        for cnt in xrange(len(flags) - 1):
            bit = int(flags[cnt])
            # grab the description for this bit
            self.data["Link_Flags"].append(self.flag_hash[cnt][bit])

        # File Attributes 4bytes@18h = 24d
        file_attrib = self.read_unpack_bin(24, 4)
        for cnt in xrange(0, 14):
            bit = int(file_attrib[cnt])
            # grab the description for this bit
            if bit == 1:
                self.data["File_Attributes"].append(self.file_hash[cnt][1])

        # Create time 8bytes @ 1ch = 28
        create_time = self.reverse_hex(self.read_unpack(28, 8))
        self.data["Create_Time"] = self.ms_time_to_unix_str(int(create_time, 16))

        # Access time 8 bytes@ 0x24 = 36D
        access_time = self.reverse_hex(self.read_unpack(36, 8))
        self.data["Access_Time"] = self.ms_time_to_unix_str(int(access_time, 16))

        # Modified Time8b @ 0x2C = 44D
        modified_time = self.reverse_hex(self.read_unpack(44, 8))
        self.data["Modified_Time"] = self.ms_time_to_unix_str(int(modified_time, 16))

        # Target File length starts @ 34h = 52d
        length_hex = self.reverse_hex(self.read_unpack(52, 4))
        length = int(length_hex, 16)
        self.data["Length"] = str(length)

        # Icon File info starts @ 38h = 56d
        icon_index_hex = self.reverse_hex(self.read_unpack(56, 4))
        self.data["Icon_Index"] = str(int(icon_index_hex, 16))

        # show windows starts @3Ch = 60d
        show_wnd_hex = self.reverse_hex(self.read_unpack(60, 1))
        show_wnd = int(show_wnd_hex, 16)
        self.data["ShowWnd"] = self.show_wnd_hash[show_wnd]

        # hot key starts @40h = 64d
        hotkey_hex = self.reverse_hex(self.read_unpack(64, 4))
        self.data["HotKey"] = str(int(hotkey_hex, 16))
        # End of flag parsing

        # get the number of items
        items_hex = self.reverse_hex(self.read_unpack(76, 2))
        items = int(items_hex, 16)
        list_end = 78 + items
        struct_start = list_end
        first_off_off = struct_start + 4
        vol_flags_off = struct_start + 8
        local_vol_off = struct_start + 12
        base_path_off = struct_start + 16
        net_vol_off = struct_start + 20
        rem_path_off = struct_start + 24

        # Structure length
        struct_len_hex = self.reverse_hex(self.read_unpack(struct_start, 4))
        struct_len = int(struct_len_hex, 16)
        struct_end = struct_start + struct_len

        # First offset after struct - Should be 1C under normal circumstances
        first_off = self.read_unpack(first_off_off, 1)

        # File location flags
        vol_flags = self.read_unpack_bin(vol_flags_off, 1)

        # Local volume table
        # Random garbage if bit0 is clear in volume flags
        if vol_flags[:2] == "10":
            target = {}
            target["Volume"] = "Local"

            # This is the offset of the local volume table within the File Info Location Structure
            loc_vol_tab_off_hex = self.reverse_hex(self.read_unpack(local_vol_off, 4))
            loc_vol_tab_off = int(loc_vol_tab_off_hex, 16)

            # This is the absolute start location of the local volume table
            loc_vol_tab_start = loc_vol_tab_off + struct_start

            # This is the length of the local volume table
            local_vol_len_hex = self.reverse_hex(self.read_unpack(loc_vol_tab_off + struct_start, 4))
            local_vol_len = int(local_vol_len_hex, 16)

            # We now have enough info to calculate the end of the local volume table.
            local_vol_tab_end = loc_vol_tab_start + local_vol_len

            # This is the volume type
            curr_tab_offset = loc_vol_tab_off + struct_start + 4
            vol_type_hex = self.reverse_hex(self.read_unpack(curr_tab_offset, 4))
            vol_type = int(vol_type_hex, 16)
            target["Volume_Type"] = str(self.vol_type_hash[vol_type])

            # Volume Serial Number
            curr_tab_offset = loc_vol_tab_off + struct_start + 8
            vol_serial = self.reverse_hex(self.read_unpack(curr_tab_offset, 4))
            target["Volume_Serial"] = str(vol_serial)

            # Get the location, and length of the volume label
            vol_label_loc = loc_vol_tab_off + struct_start + 16
            vol_label_len = local_vol_tab_end - vol_label_loc
            vol_label = self.read_unpack_ascii(vol_label_loc, vol_label_len)
            target["Volume_Label"] = str(vol_label)

            # ------------------------------------------------------------------------
            # This is the offset of the base path info within the
            # File Info structure
            # ------------------------------------------------------------------------
            base_path_off_hex = self.reverse_hex(self.read_unpack(base_path_off, 4))
            base_path_off = struct_start + int(base_path_off_hex, 16)

            # Read base path data upto NULL term
            base_path = self.read_null_term(base_path_off)
            target["Base_Path"] = str(base_path)

            self.data["Target"] = target

        # Network Volume Table
        elif vol_flags[:2] == "01":
            # Wrap this in a try/except for now until it is tested more.
            try:
                target = {}
                target["Volume"] = "Network"
                # TODO: test this section!

                net_vol_off_hex = self.reverse_hex(self.read_unpack(net_vol_off, 4))
                net_vol_off = struct_start + int(net_vol_off_hex, 16)
                net_vol_len_hex = self.reverse_hex(self.read_unpack(net_vol_off, 4))
                net_vol_len = struct_start + int(net_vol_len_hex, 16)

                # Network Share Name
                net_share_name_off = net_vol_off + 8
                net_share_name_loc_hex = self.reverse_hex(self.read_unpack(net_share_name_off, 4))
                net_share_name_loc = int(net_share_name_loc_hex, 16)

                if net_share_name_loc == 20:
                    net_share_name_loc = net_vol_off + net_share_name_loc
                    net_share_name = self.read_null_term(net_share_name_loc)
                    target["Network_Share_Name"] = str(net_share_name)

                    # Mapped Network Drive Info
                    net_share_mdrive = net_vol_off + 12
                    net_share_mdrive_hex = self.reverse_hex(self.read_unpack(net_share_mdrive, 4))
                    net_share_mdrive = int(net_share_mdrive_hex, 16)

                    if net_share_mdrive != 0:
                        net_share_mdrive = net_vol_off + net_share_mdrive
                        net_share_mdrive = self.read_null_term(net_share_mdrive)
                        target["Mapped_Drive"] = str(net_share_mdrive)

                else:
                    log.error("Net Share Name offset should always be 14h")

            except Exception as e:
                log.error("Exception {} occurred when processing Network Volume Table".format(str(e)))

        else:
            log.warn("Unknown volume flags observed")

        # Remaining path
        rem_path_off_hex = self.reverse_hex(self.read_unpack(rem_path_off, 4))
        rem_path_off = struct_start + int(rem_path_off_hex, 16)
        rem_data = self.read_null_term(rem_path_off)
        self.data["Remaining_Path"] = str(rem_data)

        # ------------------------------------------------------------------------
        # End of FileInfo Structure
        # ------------------------------------------------------------------------

        # The next starting location is the end of the structure
        next_loc = struct_end

        if flags[2] == "1":
            addnl_text, next_loc = self.add_info(next_loc)
            self.data["Parsed_Flags"]["Description"] = str(addnl_text.decode('utf-16le', errors='ignore'))

        if flags[3] == "1":
            addnl_text, next_loc = self.add_info(next_loc)
            self.data["Parsed_Flags"]["Relative_Path"] = str(addnl_text.decode('utf-16le', errors='ignore'))

        if flags[4] == "1":
            addnl_text, next_loc = self.add_info(next_loc)
            self.data["Parsed_Flags"]["Working_Dir"] = str(addnl_text.decode('utf-16le', errors='ignore'))

        if flags[5] == "1":
            addnl_text, next_loc = self.add_info(next_loc)
            self.data["Parsed_Flags"]["Command_Line"] = str(addnl_text.decode('utf-16le', errors='ignore'))

        if flags[6] == "1":
            addnl_text, next_loc = self.add_info(next_loc)
            self.data["Parsed_Flags"]["Icon_Filename"] = str(addnl_text.decode('utf-16le', errors='ignore'))

        self.lnk_close()
        return self.data
