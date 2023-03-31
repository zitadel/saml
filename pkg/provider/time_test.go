package provider

import (
	"testing"
	"time"
)

const (
	otherTimeFormat = "2006-01-02T15:04:05.999Z"
)

func TestTime_checkIfRequestTimeIsStillValid(t *testing.T) {
	type args struct {
		notBefore    string
		notOnOrAfter string
	}
	now := time.Now().UTC()

	tests := []struct {
		name string
		args args
		res  bool
	}{
		{
			"check ok 1",
			args{
				notBefore:    now.Add(-1 * time.Minute).Format(DefaultTimeFormat),
				notOnOrAfter: now.Add(1 * time.Minute).Format(DefaultTimeFormat),
			},
			false,
		},
		{
			"check ok 2",
			args{
				notBefore:    now.Add(-1 * time.Minute).Format(DefaultTimeFormat),
				notOnOrAfter: now.Add(5 * time.Minute).Format(DefaultTimeFormat),
			},
			false,
		},
		{
			"check ok 3",
			args{
				notBefore:    now.Add(-5 * time.Minute).Format(DefaultTimeFormat),
				notOnOrAfter: now.Add(5 * time.Minute).Format(DefaultTimeFormat),
			},
			false,
		},
		{
			"check ok otherformat",
			args{
				notBefore:    now.Add(-5 * time.Minute).Format(otherTimeFormat),
				notOnOrAfter: now.Add(5 * time.Minute).Format(otherTimeFormat),
			},
			false,
		},
		{
			"check not ok 1",
			args{
				notBefore:    now.Add(1 * time.Minute).Format(DefaultTimeFormat),
				notOnOrAfter: now.Add(5 * time.Minute).Format(DefaultTimeFormat),
			},
			true,
		},
		{
			"check not ok 2",
			args{
				notBefore:    now.Add(-5 * time.Minute).Format(DefaultTimeFormat),
				notOnOrAfter: now.Add(-1 * time.Minute).Format(DefaultTimeFormat),
			},
			true,
		},
		{
			"check not ok otherFormat",
			args{
				notBefore:    now.Add(-5 * time.Minute).Format(otherTimeFormat),
				notOnOrAfter: now.Add(-1 * time.Minute).Format(otherTimeFormat),
			},
			true,
		},
		{
			"check ok no times",
			args{
				notBefore:    "",
				notOnOrAfter: "",
			},
			false,
		},
		{
			"check ok only notOnOrAfter",
			args{
				notBefore:    "",
				notOnOrAfter: now.Add(1 * time.Minute).Format(DefaultTimeFormat),
			},
			false,
		},
		{
			"check not ok only notOnOrAfter",
			args{
				notBefore:    "",
				notOnOrAfter: now.Add(-1 * time.Minute).Format(DefaultTimeFormat),
			},
			true,
		},
		{
			"check not ok only notBefore",
			args{
				notBefore:    now.Add(1 * time.Minute).Format(DefaultTimeFormat),
				notOnOrAfter: "",
			},
			true,
		},
		{
			"check ok only notBefore",
			args{
				notBefore:    now.Add(-1 * time.Minute).Format(DefaultTimeFormat),
				notOnOrAfter: "",
			},
			false,
		},
		{
			"check cant parse notBefore",
			args{
				notBefore:    "what time is it?",
				notOnOrAfter: "",
			},
			true,
		},
		{
			"check cant parse notOnOrAfter",
			args{
				notBefore:    "",
				notOnOrAfter: "what time is it?",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notBeforeF := func() string {
				return tt.args.notBefore
			}
			notOnOrAfterF := func() string {
				return tt.args.notOnOrAfter
			}

			errF := checkIfRequestTimeIsStillValid(notBeforeF, notOnOrAfterF, DefaultTimeFormat)
			err := errF()
			if (err != nil) != tt.res {
				t.Errorf("ParseCertificates() got = %v, want %v", err != nil, tt.res)
			}
		})
	}
}
