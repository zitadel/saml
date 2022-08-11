package checker

import "github.com/zitadel/logging"

type Checker struct {
	steps []step
}

type step func() bool

func (c *Checker) StepCount() int {
	return len(c.steps)
}

func (c *Checker) CheckFailed() bool {
	for _, step := range c.steps {
		if step() {
			return true
		}
	}
	return false
}

func (c *Checker) WithValueNotEmptyCheck(valueName string, value func() string, errorFunc func()) *Checker {
	c.addStep(func() bool {
		if value() == "" {
			logging.Errorf("empty value %s", valueName)
			errorFunc()
			return true
		}
		return false
	})

	return c
}

func (c *Checker) WithValuesNotEmptyCheck(values func() []string, errorFunc func()) *Checker {
	c.addStep(func() bool {
		for _, value := range values() {
			if value == "" {
				logging.Errorf("empty value")
				errorFunc()
				return true
			}
		}
		return false
	})
	return c
}

func (c *Checker) WithValueLengthCheck(valueName string, value func() string, minlength, maxlength int, errorFunc func()) *Checker {
	c.addStep(func() bool {
		if (minlength > 0 && len(value()) < minlength) || (maxlength > 0 && len(value()) > maxlength) {
			logging.Errorf("error with value length %s", valueName)
			errorFunc()
			return true
		}

		return false
	})

	return c
}

func (c *Checker) WithValueEqualsCheck(valueName string, value func() string, equal func() string, errorFunc func()) *Checker {
	c.addStep(func() bool {
		if value() != equal() {
			logging.Errorf("value not equal %s: %s, %s", valueName, value(), equal())
			errorFunc()
			return true
		}

		return false
	})

	return c
}

func (c *Checker) WithConditionalValueNotEmpty(cond func() bool, valueName string, value func() string, errorFunc func()) *Checker {
	c.addStep(func() bool {
		if cond() {
			if value() == "" {
				logging.Errorf("empty value %s", valueName)
				errorFunc()
				return true
			}
		}
		return false
	})

	return c
}

func (c *Checker) WithConditionalLogicStep(cond func() bool, logic func() error, errorFunc func()) *Checker {
	c.addStep(func() bool {
		if cond() {
			if err := logic(); err != nil {
				logging.Error(err)
				errorFunc()
				return true
			}
		}
		return false
	})

	return c
}

func (c *Checker) WithLogicStep(logic func() error, errorFunc func()) *Checker {
	c.addStep(func() bool {
		if err := logic(); err != nil {
			logging.Error(err)
			errorFunc()
			return true
		}
		return false
	})
	return c
}

func (c *Checker) WithValueStep(logic func()) *Checker {
	c.addStep(func() bool {
		logic()
		return false
	})

	return c
}

func (c *Checker) addStep(f step) {
	c.steps = append(c.steps, f)
}
