package zip

import (
	"encoding/binary"
	"hash/crc32"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
)

// Legacy Decoders configuration.
// They are automatically initialized based on the system locale during init().
// You can override them manually if you need strict enforcement.
var (
	OEMDecoder    *encoding.Decoder = charmap.CodePage437.NewDecoder()
	ANSIDecoder   *encoding.Decoder = charmap.Windows1252.NewDecoder()
	SystemDecoder *encoding.Decoder = charmap.CodePage437.NewDecoder()
)

func init() {
	initSystemLocales()
}

var lcToOemTable = map[string]string{
	"af_ZA": "IBM850", "ar_SA": "IBM720", "ar_LB": "IBM720", "ar_EG": "IBM720",
	"ar_DZ": "IBM720", "ar_BH": "IBM720", "ar_IQ": "IBM720", "ar_JO": "IBM720",
	"ar_KW": "IBM720", "ar_LY": "IBM720", "ar_MA": "IBM720", "ar_OM": "IBM720",
	"ar_QA": "IBM720", "ar_SY": "IBM720", "ar_TN": "IBM720", "ar_AE": "IBM720",
	"ar_YE": "IBM720", "ast_ES": "IBM850", "az_AZ@cyrillic": "IBM866", "az_AZ": "IBM857",
	"be_BY": "IBM866", "bg_BG": "IBM866", "br_FR": "IBM850", "ca_ES": "IBM850",
	"zh_CN": "GBK", "zh_TW": "BIG5", "kw_GB": "IBM850", "cs_CZ": "IBM852",
	"cy_GB": "IBM850", "da_DK": "IBM850", "de_AT": "IBM850", "de_LI": "IBM850",
	"de_LU": "IBM850", "de_CH": "IBM850", "de_DE": "IBM850", "el_GR": "IBM737",
	"en_AU": "IBM850", "en_CA": "IBM850", "en_GB": "IBM850", "en_IE": "IBM850",
	"en_JM": "IBM850", "en_BZ": "IBM850", "en_PH": "IBM437", "en_ZA": "IBM437",
	"en_TT": "IBM850", "en_US": "IBM437", "en_ZW": "IBM437", "en_NZ": "IBM850",
	"es_PA": "IBM850", "es_BO": "IBM850", "es_CR": "IBM850", "es_DO": "IBM850",
	"es_SV": "IBM850", "es_EC": "IBM850", "es_GT": "IBM850", "es_HN": "IBM850",
	"es_NI": "IBM850", "es_CL": "IBM850", "es_MX": "IBM850", "es_ES": "IBM850",
	"es_CO": "IBM850", "es_PE": "IBM850", "es_AR": "IBM850", "es_PR": "IBM850",
	"es_VE": "IBM850", "es_UY": "IBM850", "es_PY": "IBM850", "et_EE": "IBM775",
	"eu_ES": "IBM850", "fa_IR": "IBM720", "fi_FI": "IBM850", "fo_FO": "IBM850",
	"fr_FR": "IBM850", "fr_BE": "IBM850", "fr_CA": "IBM850", "fr_LU": "IBM850",
	"fr_MC": "IBM850", "fr_CH": "IBM850", "ga_IE": "IBM437", "gd_GB": "IBM850",
	"gv_IM": "IBM850", "gl_ES": "IBM850", "he_IL": "IBM862", "hr_HR": "IBM852",
	"hu_HU": "IBM852", "id_ID": "IBM850", "is_IS": "IBM850", "it_IT": "IBM850",
	"it_CH": "IBM850", "iv_IV": "IBM437", "ja_JP": "CP932", "kk_KZ": "IBM866",
	"ko_KR": "CP949", "ky_KG": "IBM866", "lt_LT": "IBM775", "lv_LV": "IBM775",
	"mk_MK": "IBM866", "mn_MN": "IBM866", "ms_BN": "IBM850", "ms_MY": "IBM850",
	"nl_BE": "IBM850", "nl_NL": "IBM850", "nl_SR": "IBM850", "nn_NO": "IBM850",
	"nb_NO": "IBM850", "pl_PL": "IBM852", "pt_BR": "IBM850", "pt_PT": "IBM850",
	"rm_CH": "IBM850", "ro_RO": "IBM852", "ru_RU": "IBM866", "sk_SK": "IBM852",
	"sl_SI": "IBM852", "sq_AL": "IBM852", "sr_RS@latin": "IBM852", "sr_RS": "IBM855",
	"sv_SE": "IBM850", "sv_FI": "IBM850", "sw_KE": "IBM437", "th_TH": "TIS-620",
	"tr_TR": "IBM857", "tt_RU": "IBM866", "uk_UA": "IBM866", "ur_PK": "IBM720",
	"uz_UZ@cyrillic": "IBM866", "uz_UZ": "IBM857", "vi_VN": "WINDOWS-1258",
	"wa_BE": "IBM850", "zh_HK": "BIG5-HKSCS", "zh_SG": "GBK",
}

var lcToAnsiTable = map[string]string{
	"af_ZA": "WINDOWS-1252", "ar_SA": "WINDOWS-1256", "ar_LB": "WINDOWS-1256", "ar_EG": "WINDOWS-1256",
	"ar_DZ": "WINDOWS-1256", "ar_BH": "WINDOWS-1256", "ar_IQ": "WINDOWS-1256", "ar_JO": "WINDOWS-1256",
	"ar_KW": "WINDOWS-1256", "ar_LY": "WINDOWS-1256", "ar_MA": "WINDOWS-1256", "ar_OM": "WINDOWS-1256",
	"ar_QA": "WINDOWS-1256", "ar_SY": "WINDOWS-1256", "ar_TN": "WINDOWS-1256", "ar_AE": "WINDOWS-1256",
	"ar_YE": "WINDOWS-1256", "ast_ES": "WINDOWS-1252", "az_AZ@cyrillic": "WINDOWS-1251", "az_AZ": "WINDOWS-1254",
	"be_BY": "WINDOWS-1251", "bg_BG": "WINDOWS-1251", "br_FR": "WINDOWS-1252", "ca_ES": "WINDOWS-1252",
	"zh_CN": "GBK", "zh_TW": "BIG5", "kw_GB": "WINDOWS-1252", "cs_CZ": "WINDOWS-1250",
	"cy_GB": "WINDOWS-1252", "da_DK": "WINDOWS-1252", "de_AT": "WINDOWS-1252", "de_LI": "WINDOWS-1252",
	"de_LU": "WINDOWS-1252", "de_CH": "WINDOWS-1252", "de_DE": "WINDOWS-1252", "el_GR": "WINDOWS-1253",
	"en_AU": "WINDOWS-1252", "en_CA": "WINDOWS-1252", "en_GB": "WINDOWS-1252", "en_IE": "WINDOWS-1252",
	"en_JM": "WINDOWS-1252", "en_BZ": "WINDOWS-1252", "en_PH": "WINDOWS-1252", "en_ZA": "WINDOWS-1252",
	"en_TT": "WINDOWS-1252", "en_US": "WINDOWS-1252", "en_ZW": "WINDOWS-1252", "en_NZ": "WINDOWS-1252",
	"es_PA": "WINDOWS-1252", "es_BO": "WINDOWS-1252", "es_CR": "WINDOWS-1252", "es_DO": "WINDOWS-1252",
	"es_SV": "WINDOWS-1252", "es_EC": "WINDOWS-1252", "es_GT": "WINDOWS-1252", "es_HN": "WINDOWS-1252",
	"es_NI": "WINDOWS-1252", "es_CL": "WINDOWS-1252", "es_MX": "WINDOWS-1252", "es_ES": "WINDOWS-1252",
	"es_CO": "WINDOWS-1252", "es_PE": "WINDOWS-1252", "es_AR": "WINDOWS-1252",
	"es_PR": "WINDOWS-1252", "es_VE": "WINDOWS-1252", "es_UY": "WINDOWS-1252", "es_PY": "WINDOWS-1252",
	"et_EE": "WINDOWS-1257", "eu_ES": "WINDOWS-1252", "fa_IR": "WINDOWS-1256", "fi_FI": "WINDOWS-1252",
	"fo_FO": "WINDOWS-1252", "fr_FR": "WINDOWS-1252", "fr_BE": "WINDOWS-1252", "fr_CA": "WINDOWS-1252",
	"fr_LU": "WINDOWS-1252", "fr_MC": "WINDOWS-1252", "fr_CH": "WINDOWS-1252", "ga_IE": "WINDOWS-1252",
	"gd_GB": "WINDOWS-1252", "gv_IM": "WINDOWS-1252", "gl_ES": "WINDOWS-1252", "he_IL": "WINDOWS-1255",
	"hr_HR": "WINDOWS-1250", "hu_HU": "WINDOWS-1250", "id_ID": "WINDOWS-1252", "is_IS": "WINDOWS-1252",
	"it_IT": "WINDOWS-1252", "it_CH": "WINDOWS-1252", "iv_IV": "WINDOWS-1252", "ja_JP": "CP932",
	"kk_KZ": "WINDOWS-1251", "ko_KR": "CP949", "ky_KG": "WINDOWS-1251", "lt_LT": "WINDOWS-1257",
	"lv_LV": "WINDOWS-1257", "mk_MK": "WINDOWS-1251", "mn_MN": "WINDOWS-1251", "ms_BN": "WINDOWS-1252",
	"ms_MY": "WINDOWS-1252", "nl_BE": "WINDOWS-1252", "nl_NL": "WINDOWS-1252", "nl_SR": "WINDOWS-1252",
	"nn_NO": "WINDOWS-1252", "nb_NO": "WINDOWS-1252", "pl_PL": "WINDOWS-1250", "pt_BR": "WINDOWS-1252",
	"pt_PT": "WINDOWS-1252", "rm_CH": "WINDOWS-1252", "ro_RO": "WINDOWS-1250", "ru_RU": "WINDOWS-1251",
	"sk_SK": "WINDOWS-1250", "sl_SI": "WINDOWS-1250", "sq_AL": "WINDOWS-1250", "sr_RS@latin": "WINDOWS-1250",
	"sr_RS": "WINDOWS-1251", "sv_SE": "WINDOWS-1252", "sv_FI": "WINDOWS-1252", "sw_KE": "WINDOWS-1252",
	"th_TH": "WINDOWS-874", "tr_TR": "WINDOWS-1254", "tt_RU": "WINDOWS-1251", "uk_UA": "WINDOWS-1251",
	"ur_PK": "WINDOWS-1256", "uz_UZ@cyrillic": "WINDOWS-1251", "uz_UZ": "WINDOWS-1254", "vi_VN": "WINDOWS-1258",
	"wa_BE": "WINDOWS-1252", "zh_HK": "BIG5-HKSCS", "zh_SG": "GBK",
}

func getEncodingByName(name string) encoding.Encoding {
	htmlName := name
	switch name {
	case "IBM437": htmlName = "cp437"
	case "IBM850": htmlName = "cp850"
	case "IBM852": htmlName = "cp852"
	case "IBM866": htmlName = "cp866"
	case "IBM862": htmlName = "cp862"
	case "IBM720": htmlName = "windows-1256" // Fallback
	case "IBM737": htmlName = "windows-1253" // Fallback
	case "IBM775": htmlName = "windows-1257" // Fallback
	case "IBM857": htmlName = "windows-1254" // Fallback
	case "IBM855": htmlName = "cp855"
	case "CP932": htmlName = "shift_jis"
	case "CP949": htmlName = "euc-kr"
	case "TIS-620": htmlName = "windows-874"
	}
	enc, err := htmlindex.Get(htmlName)
	if err == nil {
		return enc
	}
	return nil
}

// decodeText applies the heuristic algorithm (from far2l/Wikipedia) to properly
// decode legacy encodings in zip file names and comments.
//
// 1. Check for the presence of the Unicode Path/Comment Extra Field (0x7075 / 0x6375).
// 2. Check for the presence of flag 11 (EFS UTF-8).
// 3. If OS = 11 (NTFS) and PackVer >= 20 -> ANSI.
// 4. If OS = 0 (FAT) and 25 <= PackVer <= 40 -> Central header is OEM (what we read here).
// 5. If OS = 0, 6 (HPFS), 11 -> OEM.
// 6. Otherwise -> System.
func decodeText(raw []byte, isUTF8Flag bool, packOS byte, packVer uint16, extra []byte, isComment bool) string {
	if len(raw) == 0 {
		return ""
	}

	// 1. Unicode Extra Field
	targetID := uint16(unicodePathExtraID)
	if isComment {
		targetID = unicodeCommentExtraID
	}

	if unicodeText := parseUnicodeExtraField(extra, targetID, raw); unicodeText != "" {
		return unicodeText
	}

	// 2. Bit 11 is set or OS is Unix-based (always assumes UTF-8)
	if isUTF8Flag || packOS == creatorUnix || packOS == creatorMacOSX {
		return string(raw)
	}

	// 3-6. Apply Heuristics
	var dec *encoding.Decoder

	if packOS == creatorNTFS && packVer >= 20 {
		dec = ANSIDecoder
	} else if packOS == creatorFAT && packVer >= 25 && packVer <= 40 {
		// Local is ANSI, Central is OEM. archive/zip reads central directory headers.
		dec = OEMDecoder
	} else if packOS == creatorFAT || packOS == creatorHPFS || packOS == creatorNTFS {
		dec = OEMDecoder
	} else {
		dec = SystemDecoder
	}

	if dec != nil {
		if res, err := dec.Bytes(raw); err == nil {
			return string(res)
		}
	}

	// Fallback if all else fails
	return string(raw)
}

// parseUnicodeExtraField extracts the Info-ZIP Unicode Extra Field (0x7075 or 0x6375).
// Format:
// 1 byte version (must be 1)
// 4 bytes CRC32 of the original (non-UTF8) string
// N bytes UTF-8 string
func parseUnicodeExtraField(extra []byte, targetID uint16, rawData []byte) string {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[:2])
		size := binary.LittleEndian.Uint16(extra[2:4])
		extra = extra[4:]

		if int(size) > len(extra) {
			break
		}

		if tag == targetID && size >= 5 {
			version := extra[0]
			if version == 1 {
				expectedCRC := binary.LittleEndian.Uint32(extra[1:5])
				actualCRC := crc32.ChecksumIEEE(rawData)

				if expectedCRC == actualCRC {
					utf8str := string(extra[5:size])
					if utf8.ValidString(utf8str) {
						return utf8str
					}
				}
			}
		}

		extra = extra[size:]
	}
	return ""
}