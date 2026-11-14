package cmd

import "testing"

func TestDoctorCommandRegistered(t *testing.T) {
	found, _, err := rootCmd.Find([]string{"doctor"})
	if err != nil {
		t.Fatalf("find doctor command: %v", err)
	}
	if found != doctorCmd {
		t.Fatal("doctor command is not registered on the root command")
	}
	if flag := doctorCmd.Flags().Lookup("json"); flag == nil {
		t.Fatal("doctor command must expose --json")
	}
}

func TestDoctorDefaults(t *testing.T) {
	if flag := doctorCmd.Flags().Lookup("state-file"); flag == nil || flag.DefValue != defaultDoctorStateFile {
		t.Fatalf("unexpected state-file default: %+v", flag)
	}
	if flag := doctorCmd.Flags().Lookup("cache-dir"); flag == nil || flag.DefValue != defaultBlocklistCacheDir() {
		t.Fatalf("unexpected cache-dir default: %+v", flag)
	}
}
