package podkop

import "testing"

func TestPickAssets(t *testing.T) {
	as := []ghAsset{
		{Name: "luci-app-podkop-0.7.23-r1.apk"}, {Name: "luci-app-podkop-v0.7.23-r1-all.ipk"},
		{Name: "luci-i18n-podkop-ru-0.7.23.apk"}, {Name: "luci-i18n-podkop-ru-0.7.23.ipk"},
		{Name: "podkop-0.7.23-r1.apk"}, {Name: "podkop-v0.7.23-r1-all.ipk"},
	}
	for ext, want := range map[string][3]string{
		".ipk": {"podkop-v0.7.23-r1-all.ipk", "luci-app-podkop-v0.7.23-r1-all.ipk", "luci-i18n-podkop-ru-0.7.23.ipk"},
		".apk": {"podkop-0.7.23-r1.apk", "luci-app-podkop-0.7.23-r1.apk", "luci-i18n-podkop-ru-0.7.23.apk"},
	} {
		got, err := pickAssets(as, ext)
		if err != nil || len(got) != 3 {
			t.Fatal(ext, got, err)
		}
		for i := range want {
			if got[i].Name != want[i] {
				t.Errorf("%s[%d] = %s, want %s", ext, i, got[i].Name, want[i])
			}
		}
	}
	if _, err := pickAssets(as[:1], ".ipk"); err == nil {
		t.Error("ожидалась ошибка")
	}
}
