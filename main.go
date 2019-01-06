package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"github.com/folbricht/pefile"
	"hash/adler32"
	"hash/crc32"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type InnoSetupMagic struct {
	Magic   []byte
	Version InnoSetupVersion
}
type InnoSetupDataVersion struct {
	Magic   string
	Version InnoSetupVersion
	Unicode bool
}
type InnoSetupVersion struct {
	Major    int
	Minor    int
	Patch    int
	SubPatch int
}

func (v InnoSetupVersion) greaterEqual(version InnoSetupVersion) bool {
	vInt := v.Major*1000000 + v.Minor*10000 + v.Patch*100 + v.SubPatch
	versionInt := version.Major*1000000 + version.Minor*10000 + version.Patch*100 + version.SubPatch
	return vInt >= versionInt
}

var known_setup_loader_versions = [...]InnoSetupMagic{
	{[]byte{0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0x30, 0x32, 0x87, 0x65, 0x56, 0x78}, InnoSetupVersion{1, 2, 10, 0}},
	{[]byte{0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0x30, 0x34, 0x87, 0x65, 0x56, 0x78}, InnoSetupVersion{4, 0, 0, 0}},
	{[]byte{0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0x30, 0x35, 0x87, 0x65, 0x56, 0x78}, InnoSetupVersion{4, 0, 3, 0}},
	{[]byte{0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0x30, 0x36, 0x87, 0x65, 0x56, 0x78}, InnoSetupVersion{4, 0, 10, 0}},
	{[]byte{0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0x30, 0x37, 0x87, 0x65, 0x56, 0x78}, InnoSetupVersion{4, 1, 6, 0}},
	{[]byte{0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0xcd, 0xe6, 0xd7, 0x7b, 0x0b, 0x2a}, InnoSetupVersion{5, 1, 5, 0}},
	{[]byte{0x6e, 0x53, 0x35, 0x57, 0x37, 0x64, 0x54, 0x83, 0xaa, 0x1b, 0x0f, 0x6a}, InnoSetupVersion{5, 1, 5, 0}},
}

var known_version = [...]InnoSetupDataVersion{
	InnoSetupDataVersion{"Inno Setup Setup Data (1.3.21)", InnoSetupVersion{1, 3, 21, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (1.3.25)", InnoSetupVersion{1, 3, 25, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.0)", InnoSetupVersion{2, 0, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.1)", InnoSetupVersion{2, 0, 1, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.2)", InnoSetupVersion{2, 0, 2, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.5)", InnoSetupVersion{2, 0, 5, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.6a)", InnoSetupVersion{2, 0, 6, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.7)", InnoSetupVersion{2, 0, 7, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.8)", InnoSetupVersion{2, 0, 8, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.11)", InnoSetupVersion{2, 0, 11, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.17)", InnoSetupVersion{2, 0, 17, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (2.0.18)", InnoSetupVersion{2, 0, 18, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (3.0.0a)", InnoSetupVersion{3, 0, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (3.0.1)", InnoSetupVersion{3, 0, 1, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (3.0.3)", InnoSetupVersion{3, 0, 3, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (3.0.4)", InnoSetupVersion{3, 0, 4, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (3.0.5)", InnoSetupVersion{3, 0, 5, 0}, false},
	InnoSetupDataVersion{"My Inno Setup Extensions Setup Data (3.0.6.1)", InnoSetupVersion{3, 0, 6, 1}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.0.0a)", InnoSetupVersion{4, 0, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.0.1)", InnoSetupVersion{4, 0, 1, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.0.3)", InnoSetupVersion{4, 0, 3, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.0.5)", InnoSetupVersion{4, 0, 5, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.0.9)", InnoSetupVersion{4, 0, 9, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.0.10)", InnoSetupVersion{4, 0, 10, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.0.11)", InnoSetupVersion{4, 0, 11, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.1.0)", InnoSetupVersion{4, 1, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.1.2)", InnoSetupVersion{4, 1, 2, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.1.3)", InnoSetupVersion{4, 1, 3, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.1.4)", InnoSetupVersion{4, 1, 4, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.1.5)", InnoSetupVersion{4, 1, 5, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.1.6)", InnoSetupVersion{4, 1, 6, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.1.8)", InnoSetupVersion{4, 1, 8, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.2.0)", InnoSetupVersion{4, 2, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.2.1)", InnoSetupVersion{4, 2, 1, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.2.2)", InnoSetupVersion{4, 2, 2, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.2.3)", InnoSetupVersion{4, 2, 3, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.2.4)", InnoSetupVersion{4, 2, 4, 0}, false}, // !
	InnoSetupDataVersion{"Inno Setup Setup Data (4.2.5)", InnoSetupVersion{4, 2, 5, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (4.2.6)", InnoSetupVersion{4, 2, 6, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.0.0)", InnoSetupVersion{5, 0, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.0.1)", InnoSetupVersion{5, 0, 1, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.0.3)", InnoSetupVersion{5, 0, 3, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.0.4)", InnoSetupVersion{5, 0, 4, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.1.0)", InnoSetupVersion{5, 1, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.1.2)", InnoSetupVersion{5, 1, 2, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.1.7)", InnoSetupVersion{5, 1, 7, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.1.10)", InnoSetupVersion{5, 1, 10, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.1.13)", InnoSetupVersion{5, 1, 13, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.2.0)", InnoSetupVersion{5, 2, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.2.1)", InnoSetupVersion{5, 2, 1, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.2.3)", InnoSetupVersion{5, 2, 3, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.2.5)", InnoSetupVersion{5, 2, 5, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.2.5} (u)", InnoSetupVersion{5, 2, 5, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.0)", InnoSetupVersion{5, 3, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.0} (u)", InnoSetupVersion{5, 3, 0, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.3)", InnoSetupVersion{5, 3, 3, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.3} (u)", InnoSetupVersion{5, 3, 3, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.5)", InnoSetupVersion{5, 3, 5, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.5} (u)", InnoSetupVersion{5, 3, 5, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.6)", InnoSetupVersion{5, 3, 6, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.6} (u)", InnoSetupVersion{5, 3, 6, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.7)", InnoSetupVersion{5, 3, 7, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.7} (u)", InnoSetupVersion{5, 3, 7, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.8)", InnoSetupVersion{5, 3, 8, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.8} (u)", InnoSetupVersion{5, 3, 8, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.9)", InnoSetupVersion{5, 3, 9, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.9} (u)", InnoSetupVersion{5, 3, 9, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.10)", InnoSetupVersion{5, 3, 10, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.3.10} (u)", InnoSetupVersion{5, 3, 10, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.4.2)", InnoSetupVersion{5, 4, 2, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.4.2} (u)", InnoSetupVersion{5, 4, 2, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.5.0)", InnoSetupVersion{5, 5, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.5.0} (u)", InnoSetupVersion{5, 5, 0, 0}, true},
	InnoSetupDataVersion{"!!! BlackBox v2?, marked as 5.5.0", InnoSetupVersion{5, 5, 0, 1}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.5.6)", InnoSetupVersion{5, 5, 6, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.5.6} (u)", InnoSetupVersion{5, 5, 6, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.5.7)", InnoSetupVersion{5, 5, 7, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.5.7} (u)", InnoSetupVersion{5, 5, 7, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.5.7} {U)", InnoSetupVersion{5, 5, 7, 0}, true},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.6.0)", InnoSetupVersion{5, 6, 0, 0}, false},
	InnoSetupDataVersion{"Inno Setup Setup Data (5.6.0} {u}", InnoSetupVersion{5, 6, 0, 0}, true},
}

type InnoSetupOffsetTable struct {
	Magic    []byte
	Version  InnoSetupVersion
	Revision uint32

	ExeOffset           uint32
	ExeCompressedSize   uint32
	ExeUncompressedSize uint32
	ExeChecksum         uint32

	MessageOffset uint32
	HeaderOffset  uint32
	DataOffset    uint32
}

func FindOffsetTable(bytes []byte) (i *InnoSetupOffsetTable) {
	log.Println("Function: Load")
	i = FindOffsetTableInPE(bytes)
	if i == nil {
		i = FindOffsetTableInResource(bytes)
	}
	return i
}

const SetupLoaderHeaderOffset = 0x30
const SetupLoaderHeaderMagic = 0x6f6e6e49
const ResourceNameInstaller = "11111"

func FindOffsetTableInPE(bytes []byte) (i *InnoSetupOffsetTable) {
	log.Println("Function: Load_from_exe")

	headerBytes := bytes[SetupLoaderHeaderOffset:]
	magicValue := binary.BigEndian.Uint32(headerBytes)

	if magicValue != SetupLoaderHeaderMagic {
		log.Printf("Magic missing: Was 0x%08X not 0x%08X", magicValue, SetupLoaderHeaderMagic)
		return
	}

	offset_table_offset := binary.BigEndian.Uint32(headerBytes[4:])
	not_offset_table_offset := binary.BigEndian.Uint32(headerBytes[8:])
	if offset_table_offset != ^not_offset_table_offset {
		log.Println("Offset and nor offset not identical. Double check code pl0x")
		return
	}

	return load_offsets_at(bytes, offset_table_offset)
}

func FindOffsetTableInResource(pebytes []byte) (i *InnoSetupOffsetTable) {
	log.Println("Function: LoadPeResource")
	pefile, err := pefile.New(bytes.NewReader(pebytes))

	resources, err := pefile.GetResources()
	if err != nil {
		log.Println("Could not read resources")
	}

	for _, e := range resources {
		if strings.Split(e.Name, "/")[1] != ResourceNameInstaller {
			continue
		}
		return load_offsets_at(e.Data, 0)

	}
	log.Println("Needed Resource not found")
	return i
}

func load_offsets_at(offsetBytes []byte, pos uint32) (i *InnoSetupOffsetTable) {
	log.Println("Function: load_offsets_at")
	log.Println("Loading offsets from ", pos)

	i = &InnoSetupOffsetTable{}

	offsetBytes = offsetBytes[pos:]
	i.Magic = offsetBytes[:12]

	log.Print("Found magic: ", hex.Dump(i.Magic))

	for _, e := range known_setup_loader_versions {
		if bytes.Equal(i.Magic, e.Magic) {
			log.Println("Found Version: ", e.Version)
			i.Version = e.Version
			break
		}
	}
	if (i.Version == InnoSetupVersion{0, 0, 0,0}) {
		log.Println("Unknown Magic!")
		return
	}

	checksum := crc32.New(crc32.IEEETable)
	checksum.Write(i.Magic)

	offset := 12
	if (i.Version.greaterEqual(InnoSetupVersion{5, 1, 5,0})) {
		revisionBytes := offsetBytes[offset : offset+4]
		checksum.Write(revisionBytes)
		revision := binary.LittleEndian.Uint32(revisionBytes)
		offset += 4
		if revision != 1 {
			log.Printf("Revision is not 1!! 0x%08X", revision)
		}
	}

	//Skipping 4 bytes. Something alike: 97 c2 7f 00
	checksum.Write(offsetBytes[offset : offset+4])
	offset += 4

	exeBytes := offsetBytes[offset : offset+4]
	checksum.Write(exeBytes)
	exeOffset := binary.LittleEndian.Uint32(exeBytes)
	offset += 4

	i.ExeCompressedSize = 0
	if (!i.Version.greaterEqual(InnoSetupVersion{4, 1, 6,0})) {
		exeBytes := offsetBytes[offset : offset+4]
		checksum.Write(exeBytes)
		i.ExeCompressedSize = binary.LittleEndian.Uint32(exeBytes)
		offset += 4
	}

	exeUncompressedBytes := offsetBytes[offset : offset+4]
	checksum.Write(exeUncompressedBytes)
	i.ExeUncompressedSize = binary.LittleEndian.Uint32(exeUncompressedBytes)
	offset += 4

	exe_checksum := 0
	exe_checksumBytes := offsetBytes[offset : offset+4]
	checksum.Write(exe_checksumBytes)
	if (i.Version.greaterEqual(InnoSetupVersion{4, 0, 3,0})) {
		exe_checksum := crc32.New(crc32.IEEETable)
		exe_checksum.Write(exe_checksumBytes)
	} else {
		exe_checksum := adler32.New()
		exe_checksum.Write(exe_checksumBytes)
	}
	offset += 4

	i.MessageOffset = 0
	if (!i.Version.greaterEqual(InnoSetupVersion{4, 0, 0,0})) {
		messageOffsetBytes := offsetBytes[offset : offset+4]
		i.MessageOffset = binary.LittleEndian.Uint32(messageOffsetBytes)
		offset += 4
	}

	i.HeaderOffset = binary.LittleEndian.Uint32(offsetBytes[offset : offset+4])
	checksum.Write(offsetBytes[offset : offset+4])
	offset += 4
	i.DataOffset = binary.LittleEndian.Uint32(offsetBytes[offset : offset+4])
	checksum.Write(offsetBytes[offset : offset+4])
	offset += 4

	if (i.Version.greaterEqual(InnoSetupVersion{4, 0, 10,0})) {
		expected := binary.LittleEndian.Uint32(offsetBytes[offset : offset+4])
		checksum := checksum.Sum32()
		if expected != checksum {
			log.Printf("Checksum mismatch: 0x%08X expected: 0x%08X", checksum, expected)
		}
	}
	log.Printf("exeOffset: 0x%08X", exeOffset)
	log.Printf("ExeCompressedSize: 0x%08X", i.ExeCompressedSize)
	log.Printf("ExeUncompressedSize: 0x%08X", i.ExeUncompressedSize)
	log.Printf("ExeChecksum: 0x%08X", exe_checksum)
	log.Printf("MessageOffset: 0x%08X", i.MessageOffset)
	log.Printf("HeaderOffset: 0x%08X", i.HeaderOffset)
	log.Printf("DataOffset: 0x%08X", i.DataOffset)

	//TODO report error
	return i
}

func ParseVersionData(table *InnoSetupOffsetTable, peBytes []byte) (version *InnoSetupDataVersion) {

	legacyVersion16 := "i1.2.10--16\x1a"
	legacyVersion32 := "i1.2.10--32\x1a"

	legacyBytes := peBytes[table.HeaderOffset : table.HeaderOffset+12]
	if bytes.Equal(legacyBytes, []byte(legacyVersion16)) {
		version = &InnoSetupDataVersion{legacyVersion16,InnoSetupVersion{1, 2, 10,16}, false}
	} else if bytes.Equal(legacyBytes, []byte(legacyVersion32)) {
		version = &InnoSetupDataVersion{legacyVersion32,InnoSetupVersion{1, 2, 10,32}, false}
	} else {
		//TODO only user lookup in case of fails?
		for _,e := range known_version {
			nextBytes := peBytes[table.HeaderOffset : table.HeaderOffset + uint32(len(e.Magic))]
			if(bytes.Equal(nextBytes, []byte(e.Magic))){
				log.Println("Found version: ", e.Version, " @ ", e.Magic)
				version = &e
				break;
			}
		}
	}
	return version
}

func main() {
	file, err := os.OpenFile("n1muj19w.exe", os.O_RDONLY, 0)

	bytes, err := ioutil.ReadAll(file)

	offsetTable := FindOffsetTable(bytes)
	version := ParseVersionData(offsetTable, bytes)
	if(version == nil){
		panic("PANIC!")
	}

	
	if err != nil {
		panic("PANIC!")
	}
	log.Println(offsetTable)
	log.Println(version)
	/*
	   	FLAGS(entry_types,
	   		Components,
	   		DataEntries,
	   		DeleteEntries,
	   		UninstallDeleteEntries,
	   		Directories,
	   		Files,
	   		Icons,
	   		IniEntries,
	   		Languages,
	   		Messages,
	   		Permissions,
	   		RegistryEntries,
	   		RunEntries,
	   		UninstallRunEntries,
	   		Tasks,
	   		Types,
	   		WizardImages,
	   		DecompressorDll,
	   		DecryptDll,
	   		NoSkip,
	   		NoUnknownVersion
	   	);
	   setup::info::entry_types entries = 0;
	   	if(o.list || o.test || o.extract || (o.gog_galaxy && o.list_languages)) {
	   		entries |= setup::info::Files;
	   		entries |= setup::info::Directories;
	   		entries |= setup::info::DataEntries;
	   	}
	   	if(o.list_languages) {
	   		entries |= setup::info::Languages;
	   	}
	   	if(o.gog_game_id || o.gog) {
	   		entries |= setup::info::RegistryEntries;
	   	}
	   	if(!o.extract_unknown) {
	   		entries |= setup::info::NoUnknownVersion;
	   	}

	   	if(logger::debug) {
	   		entries = setup::info::entry_types::all();
	   	}
	*/
	/*

	   	ifs.seekg(offsetTable.HeaderOffset);
	   setup::info info;
	   	try {
	   		info.load(ifs, entries);
	   	} catch(const std::ios_base::failure & e) {
	   	std::ostringstream oss;
	   		oss << "Stream error while parsing setup headers!\n";
	   		oss << " ├─ detected setup version: " << info.version << '\n';
	   		oss << " └─ error reason: " << e.what();
	   		throw format_error(oss.str());
	   	}

	   	if(o.gog_galaxy && (o.list || o.test || o.extract || o.list_languages)) {
	   	gog::parse_galaxy_files(info, o.gog);
	   	}

	   	bool multiple_sections = print_file_info(o, info);

	   std::string password;
	   	if(o.password.empty()) {
	   		if(!o.quiet && (o.list || o.test || o.extract) && (info.header.options & setup::header::EncryptionUsed)) {
	   		log_warning << "Setup contains encrypted files, use the --password option to extract them";
	   		}
	   	} else {
	   	util::from_utf8(o.password, password, info.version.codepage());
	   		if(info.header.options & setup::header::Password) {
	   		crypto::hasher checksum(info.header.password.type);
	   			checksum.update(info.header.password_salt.c_str(), info.header.password_salt.length());
	   			checksum.update(password.c_str(), password.length());
	   			if(checksum.finalize() != info.header.password) {
	   				if(o.check_password) {
	   					throw std::runtime_error("Incorrect password provided");
	   				}
	   				log_error << "Incorrect password provided";
	   				password.clear();
	   			}
	   		}
	   		#if !INNOEXTRACT_HAVE_ARC4
	   		if((o.extract || o.test) && (info.header.options & setup::header::EncryptionUsed)) {
	   		log_warning << "ARC4 decryption not supported in this build, skipping compressed chunks";
	   		}
	   		password.clear();
	   		#endif
	   	}

	   	if(!o.list && !o.test && !o.extract) {
	   		return;
	   	}

	   	if(!o.silent && multiple_sections) {
	   	std::cout << "Files:\n";
	   	}

	   	processed_entries processed = filter_entries(o, info);

	   	if(o.extract && !o.output_dir.empty()) {
	   	fs::create_directories(o.output_dir);
	   	}

	   	if(o.list || o.extract) {

	   		BOOST_FOREACH(const DirectoriesMap::value_type & i, processed.directories) {

	   			const std::string & path = i.second.path();

	   			if(o.list && !i.second.implied()) {

	   				if(!o.silent) {

	   				std::cout << " - ";
	   				std::cout << '"' << color::dim_white << path << setup::path_sep << color::reset << '"';
	   					if(i.second.has_entry()) {
	   						print_filter_info(i.second.entry());
	   					}
	   				std::cout << '\n';

	   				} else {
	   				std::cout << color::dim_white << path << setup::path_sep << color::reset << '\n';
	   				}

	   			}

	   			if(o.extract) {
	   			fs::path dir = o.output_dir / path;
	   				try {
	   					fs::create_directory(dir);
	   				} catch(...) {
	   				throw std::runtime_error("Could not create directory \"" + dir.string() + '"');
	   				}
	   			}

	   		}

	   	}

	   	typedef std::pair<const processed_file *, boost::uint64_t> output_location;
	   std::vector< std::vector<output_location> > files_for_location;
	   	files_for_location.resize(info.data_entries.size());
	   	BOOST_FOREACH(const FilesMap::value_type & i, processed.files) {
	   		const processed_file & file = i.second;
	   		files_for_location[file.entry().location].push_back(output_location(&file, 0));
	   		if(o.test || o.extract) {
	   		boost::uint64_t offset = info.data_entries[file.entry().location].uncompressed_size;
	   			BOOST_FOREACH(boost::uint32_t location, file.entry().additional_locations) {
	   				files_for_location[location].push_back(output_location(&file, offset));
	   				offset += info.data_entries[location].uncompressed_size;
	   			}
	   		}
	   	}

	   boost::uint64_t total_size = 0;

	   	typedef std::map<stream::file, size_t> Files;
	   	typedef std::map<stream::chunk, Files> Chunks;
	   	Chunks chunks;
	   	for(size_t i = 0; i < info.data_entries.size(); i++) {
	   		if(files_for_location[i].empty()) {
	   			continue;
	   		}
	   	setup::data_entry & location = info.data_entries[i];
	   		if(location.chunk.compression == stream::UnknownCompression) {
	   			location.chunk.compression = info.header.compression;
	   		}
	   		chunks[location.chunk][location.file] = i;
	   		total_size += location.uncompressed_size;
	   	}

	   boost::scoped_ptr<stream::slice_reader> slice_reader;
	   	if(o.extract || o.test) {
	   		if(offsets.data_offset) {
	   			slice_reader.reset(new stream::slice_reader(&ifs, offsets.data_offset));
	   		} else {
	   		fs::path dir = file.parent_path();
	   		std::string basename = util::as_string(file.stem());
	   		std::string basename2 = info.header.base_filename;
	   			// Prevent access to unexpected files
	   		std::replace(basename2.begin(), basename2.end(), '/', '_');
	   		std::replace(basename2.begin(), basename2.end(), '\\', '_');
	   			// Older Inno Setup versions used the basename stored in the headers, change our default accordingly
	   			if(info.version < INNO_VERSION(4, 1, 7) && !basename2.empty()) {
	   			std::swap(basename2, basename);
	   			}
	   			slice_reader.reset(new stream::slice_reader(dir, basename, basename2, info.header.slices_per_disk));
	   		}
	   	}

	   	progress extract_progress(total_size);

	   	typedef boost::ptr_map<const processed_file *, file_output> multi_part_outputs;
	   	multi_part_outputs multi_outputs;

	   	BOOST_FOREACH(const Chunks::value_type & chunk, chunks) {

	   		debug("[starting " << chunk.first.compression << " chunk @ slice " << chunk.first.first_slice
	   		<< " + " << print_hex(offsets.data_offset) << " + " << print_hex(chunk.first.offset)
	   		<< ']');

	   	stream::chunk_reader::pointer chunk_source;
	   		if((o.extract || o.test) && (chunk.first.encryption == stream::Plaintext || !password.empty())) {
	   		chunk_source = stream::chunk_reader::get(*slice_reader, chunk.first, password);
	   		}
	   	boost::uint64_t offset = 0;

	   		BOOST_FOREACH(const Files::value_type & location, chunk.second) {
	   			const stream::file & file = location.first;
	   			const std::vector<output_location> & output_locations = files_for_location[location.second];

	   			if(file.offset > offset) {
	   				debug("discarding " << print_bytes(file.offset - offset)
	   				<< " @ " << print_hex(offset));
	   				if(chunk_source.get()) {
	   				util::discard(*chunk_source, file.offset - offset);
	   				}
	   			}

	   			// Print filename and size
	   			if(o.list) {

	   				extract_progress.clear(DeferredClear);

	   				if(!o.silent) {

	   					bool named = false;
	   				boost::uint64_t size = 0;
	   					const crypto::checksum * checksum = NULL;
	   					BOOST_FOREACH(const output_location & output, output_locations) {
	   						if(output.second != 0) {
	   							continue;
	   						}
	   						if(output.first->entry().size != 0) {
	   							if(size != 0 && size != output.first->entry().size) {
	   								log_warning << "Mismatched output sizes";
	   							}
	   							size = output.first->entry().size;
	   						}
	   						if(output.first->entry().checksum.type != crypto::None) {
	   							if(checksum && *checksum != output.first->entry().checksum) {
	   								log_warning << "Mismatched output checksums";
	   							}
	   							checksum = &output.first->entry().checksum;
	   						}
	   						if(named) {
	   						std::cout << ", ";
	   						} else {
	   						std::cout << " - ";
	   							named = true;
	   						}
	   						if(chunk.first.encryption != stream::Plaintext) {
	   							if(password.empty()) {
	   							std::cout << '"' << color::dim_yellow << output.first->path() << color::reset << '"';
	   							} else {
	   							std::cout << '"' << color::yellow << output.first->path() << color::reset << '"';
	   							}
	   						} else {
	   						std::cout << '"' << color::white << output.first->path() << color::reset << '"';
	   						}
	   						print_filter_info(output.first->entry());
	   					}

	   					if(named) {
	   						if(o.list_sizes) {
	   							print_size_info(file, size);
	   						}
	   						if(o.list_checksums) {
	   						std::cout << ' ';
	   							print_checksum_info(file, checksum);
	   						}
	   						if(chunk.first.encryption != stream::Plaintext && password.empty()) {
	   						std::cout << " - encrypted";
	   						}
	   					std::cout << '\n';
	   					}

	   				} else {
	   					BOOST_FOREACH(const output_location & output, output_locations) {
	   						if(output.second == 0) {
	   							const processed_file * fileinfo = output.first;
	   							if(o.list_sizes) {
	   							boost::uint64_t size = fileinfo->entry().size;
	   							std::cout << color::dim_cyan << (size != 0 ? size : file.size) << color::reset << ' ';
	   							}
	   							if(o.list_checksums) {
	   								print_checksum_info(file, &fileinfo->entry().checksum);
	   							std::cout << ' ';
	   							}
	   						std::cout << color::white << fileinfo->path() << color::reset << '\n';
	   						}
	   					}
	   				}

	   				bool updated = extract_progress.update(0, true);
	   				if(!updated && (o.extract || o.test)) {
	   				std::cout.flush();
	   				}

	   			}

	   			// Seek to the correct position within the chunk
	   			if(chunk_source.get() && file.offset < offset) {
	   			std::ostringstream oss;
	   				oss << "Bad offset while extracting files: file start (" << file.offset
	   				<< ") is before end of previous file (" << offset << ")!";
	   				throw format_error(oss.str());
	   			}
	   			offset = file.offset + file.size;

	   			if(!chunk_source.get()) {
	   				continue; // Not extracting/testing this file
	   			}

	   		crypto::checksum checksum;

	   			// Open input file
	   		stream::file_reader::pointer file_source;
	   			file_source = stream::file_reader::get(*chunk_source, file, &checksum);

	   			// Open output files
	   		boost::ptr_vector<file_output> single_outputs;
	   		std::vector<file_output *> outputs;
	   			BOOST_FOREACH(const output_location & location, output_locations) {
	   				const processed_file * fileinfo = location.first;
	   				try {

	   					if(!o.extract && fileinfo->entry().checksum.type == crypto::None) {
	   					continue;
	   				}

	   					// Re-use existing file output for multi-part files
	   					file_output * output = NULL;
	   					if(fileinfo->is_multipart()) {
	   					multi_part_outputs::iterator it = multi_outputs.find(fileinfo);
	   					if(it != multi_outputs.end()) {
	   					output = it->second;
	   				}
	   				}

	   					if(!output) {
	   					output = new file_output(o.output_dir, fileinfo, o.extract);
	   					if(fileinfo->is_multipart()) {
	   					multi_outputs.insert(fileinfo, output);
	   				} else {
	   					single_outputs.push_back(output);
	   				}
	   				}

	   					outputs.push_back(output);

	   					output->seek(location.second);

	   				} catch(boost::bad_pointer &) {
	   					// should never happen
	   				std::terminate();
	   				}
	   			}

	   			// Copy data
	   		boost::uint64_t output_size = 0;
	   			while(!file_source->eof()) {
	   				char buffer[8192 * 10];
	   			std::streamsize buffer_size = std::streamsize(boost::size(buffer));
	   			std::streamsize n = file_source->read(buffer, buffer_size).gcount();
	   				if(n > 0) {
	   					BOOST_FOREACH(file_output * output, outputs) {
	   						bool success = output->write(buffer, size_t(n));
	   						if(!success) {
	   							throw std::runtime_error("Error writing file \"" + output->path().string() + '"');
	   						}
	   					}
	   					extract_progress.update(boost::uint64_t(n));
	   					output_size += boost::uint64_t(n);
	   				}
	   			}

	   			const setup::data_entry & data = info.data_entries[location.second];

	   			if(output_size != data.uncompressed_size) {
	   				log_warning << "Unexpected output file size: " << output_size << " != " << data.uncompressed_size;
	   			}

	   		util::time filetime = data.timestamp;
	   			if(o.extract && o.preserve_file_times && o.local_timestamps && !(data.options & data.TimeStampInUTC)) {
	   				filetime = util::to_local_time(filetime);
	   			}

	   			BOOST_FOREACH(file_output * output, outputs) {

	   				if(output->file()->is_multipart() && !output->is_complete()) {
	   					continue;
	   				}

	   				// Verify output checksum if available
	   				if(output->file()->entry().checksum.type != crypto::None) {
	   					if(output->has_checksum()) {
	   					crypto::checksum checksum = output->checksum();
	   						if(checksum != output->file()->entry().checksum) {
	   							log_warning << "Output checksum mismatch for " << output->file()->path() << ":\n"
	   							<< " ├─ actual:   " << checksum << '\n'
	   							<< " └─ expected: " << output->file()->entry().checksum;
	   							if(o.test) {
	   								throw std::runtime_error("Integrity test failed!");
	   							}
	   						}
	   					} else {
	   						// This should not happen
	   						log_warning << "Could not verify output checksum of file " << output->file()->path();
	   					}
	   				}

	   				// Adjust file timestamps
	   				if(o.extract && o.preserve_file_times) {
	   					output->close();
	   					if(!util::set_file_time(output->path(), filetime, data.timestamp_nsec)) {
	   						log_warning << "Error setting timestamp on file " << output->path();
	   					}
	   				}

	   				if(output->file()->is_multipart()) {
	   					debug("[finalizing multi-part file]");
	   					multi_outputs.erase(output->file());
	   				}

	   			}

	   			// Verify checksums
	   			if(checksum != file.checksum) {
	   				log_warning << "Checksum mismatch:\n"
	   				<< " ├─ actual:   " << checksum << '\n'
	   				<< " └─ expected: " << file.checksum;
	   				if(o.test) {
	   					throw std::runtime_error("Integrity test failed!");
	   				}
	   			}

	   		}

	   		#ifdef DEBUG
	   		if(offset < chunk.first.size) {
	   			debug("discarding " << print_bytes(chunk.first.size - offset)
	   			<< " at end of chunk @ " << print_hex(offset));
	   		}
	   		#endif
	   	}

	   	extract_progress.clear();

	   	if(!multi_outputs.empty()) {
	   		log_warning << "Incomplete multi-part files";
	   	}

	   	if(o.warn_unused || o.gog) {
	   	gog::probe_bin_files(o, info, file, offsets.data_offset == 0);
	   	}



	*/
}
