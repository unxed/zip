package zip

import "strings"

func sanitizeZoneIdentifier(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	zoneID := "3" // Default to Internet Zone (3) if parsing fails
	found := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ZoneId=") {
			val := strings.TrimPrefix(line, "ZoneId=")
			if len(val) > 0 && val[0] >= '0' && val[0] <= '4' {
				zoneID = string(val[0])
				found = true
			}
		}
	}
	if !found {
		return data
	}
	return []byte("[ZoneTransfer]\r\nZoneId=" + zoneID + "\r\n")
}