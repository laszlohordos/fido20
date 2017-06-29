package main

import (
	"fmt"
	"github.com/inconshreveable/log15"
	"github.com/jroimartin/gocui"
	"time"
)

type consoleWriter struct {
	gui  *gocui.Gui
	view *gocui.View
}

var popup func(g *gocui.Gui) error

func (c *consoleWriter) Write(p []byte) (n int, err error) {
	c.gui.Execute(func(g *gocui.Gui) error {
		n, err = c.view.Write(p)
		return nil
	})
	return
}

func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	if v, err := g.SetView("help", maxX-23, 0, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		fmt.Fprintln(v, "KEYBINDINGS")
		fmt.Fprintln(v, "Enter: Accept")
		fmt.Fprintln(v, "Space: Reject")
		fmt.Fprintln(v, "a: autoscroll")
		fmt.Fprintln(v, "↑ ↓: Seek input")
		fmt.Fprintln(v, "^C: Exit")
	}

	if v, err := g.SetView("log", 0, 0, maxX-23, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		logger.SetHandler(log15.MultiHandler(log15.StreamHandler(&consoleWriter{gui: g, view: v}, log15.LogfmtFormat()), logger.GetHandler()))
		v.Wrap = true
		v.Autoscroll = true
		v.Title = fmt.Sprintf("Authenticator AAGUID '%s'", *aaguid)

		if _, err := g.SetCurrentView("log"); err != nil {
			return err
		}
	}

	f := popup

	if f != nil {
		f(g)
	}
	return nil
}

func initKeybindings(g *gocui.Gui) error {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		return err
	}
	if err := g.SetKeybinding("log", gocui.KeyCtrlA, gocui.ModNone, autoscroll); err != nil {
		return err
	}

	if err := g.SetKeybinding("log", gocui.KeyArrowUp, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			scrollView(v, -1)
			return nil
		}); err != nil {
		return err
	}
	if err := g.SetKeybinding("log", gocui.KeyArrowDown, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			scrollView(v, 1)
			return nil
		}); err != nil {
		return err
	}
	return nil
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func autoscroll(g *gocui.Gui, v *gocui.View) error {
	v.Autoscroll = true
	return nil
}

func scrollView(v *gocui.View, dy int) error {
	if v != nil {
		v.Autoscroll = false
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox, oy+dy); err != nil {
			return err
		}
	}
	return nil
}

func cursorDown(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		_, my := v.Size()
		cx, cy := v.Cursor()
		if cy == my-1 {
			return nil
		}
		if err := v.SetCursor(cx, cy+1); err != nil {
			ox, oy := v.Origin()
			if err := v.SetOrigin(ox, oy+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func cursorUp(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		ox, oy := v.Origin()
		cx, cy := v.Cursor()
		if err := v.SetCursor(cx, cy-1); err != nil && oy > 0 {
			if err := v.SetOrigin(ox, oy-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func CredentialApproverUIFunc(done <-chan struct{}, gui *gocui.Gui) CredentialApprover {

	return func(cred Credential) bool {
		inputChan := make(chan bool, 1)

		reject := approveMsg(false, inputChan)

		popup = func(g *gocui.Gui) error {
			maxX, maxY := g.Size()
			if v, err := g.SetView("msg", (maxX-23)/2-30, maxY/2-3, (maxX-23)/2+30, maxY/2+3); err != nil {
				if err != gocui.ErrUnknownView {
					return err
				}

				if err := g.SetKeybinding(v.Name(), gocui.KeyEnter, gocui.ModNone, approveMsg(true, inputChan)); err != nil {
					return err
				}

				if err := g.SetKeybinding(v.Name(), gocui.KeySpace, gocui.ModNone, reject); err != nil {
					return err
				}

				if _, err := g.SetCurrentView(v.Name()); err != nil {
					if err != gocui.ErrUnknownView {
						return err
					}
					g.DeleteKeybindings(v.Name())
					g.DeleteView(v.Name())
					return err
				}
				v.Title = "Create Credential"
				fmt.Fprintf(v, "Relying Party ID  : %s\n", cred.RelyingParty().Id)
				fmt.Fprintf(v, "Relying Party Name: %s\n", cred.RelyingParty().Name)
				fmt.Fprintf(v, "User ID           : %s\n", cred.User().Id)
				fmt.Fprintf(v, "User Name         : %s\n", cred.User().Name)
				fmt.Fprintf(v, "User Display Name : %s\n", cred.User().DisplayName)
			}
			return nil
		}
		gui.Execute(popup)

		select {
		case c := <-inputChan:
			return c
		case <-done:
		case <-time.After(time.Duration(20) * time.Second):
			logger.Info("Timeout")
			reject(gui, nil)
		}
		return false
	}
}

func approveMsg(approve bool, resp chan<- bool) func(*gocui.Gui, *gocui.View) error {

	return func(g *gocui.Gui, _ *gocui.View) error {
		popup = nil
		select {
		case resp <- approve:
		case <-time.After(time.Duration(500) * time.Millisecond):
		}
		if _, err := g.SetCurrentView("log"); err != nil {
			return err
		}
		g.DeleteKeybindings("msg")
		if err := g.DeleteView("msg"); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
		}
		return nil
	}
}

func CredentialSelectorUIFunc(done <-chan struct{}, gui *gocui.Gui) CredentialSelector {
	return func(candidate []Credential) Credential {

		inputChan := make(chan int, 1)

		reject := selectMsg(false, inputChan)

		popup = func(g *gocui.Gui) error {

			count := len(candidate) + 2

			maxX, maxY := g.Size()
			Y := maxY/2 - (count / 2)
			if v, err := g.SetView("msg", (maxX-23)/2-40, Y, (maxX-23)/2+40, Y+count); err != nil {
				if err != gocui.ErrUnknownView {
					return err
				}

				if err := g.SetKeybinding(v.Name(), gocui.KeyArrowDown, gocui.ModNone, cursorDown); err != nil {
					return err
				}
				if err := g.SetKeybinding(v.Name(), gocui.KeyArrowUp, gocui.ModNone, cursorUp); err != nil {
					return err
				}
				if err := g.SetKeybinding(v.Name(), gocui.KeySpace, gocui.ModNone, reject); err != nil {
					return err
				}
				if err := g.SetKeybinding(v.Name(), gocui.KeyEnter, gocui.ModNone, selectMsg(true, inputChan)); err != nil {
					return err
				}

				v.Title = "Select Credential"
				v.Highlight = true
				v.SelBgColor = gocui.ColorGreen
				v.SelFgColor = gocui.ColorBlack

				v.Autoscroll = false

				fmt.Fprintln(v, "None")
				for i, c := range candidate {
					fmt.Fprintf(v, "%d %s(%s) <-[%s]\n", i, c.User().DisplayName, c.User().Id, c.RelyingParty().Id)
				}
				if count%1 != 0 {
					fmt.Fprintln(v, "None")
				}
				if _, err := g.SetCurrentView(v.Name()); err != nil {
					if err != gocui.ErrUnknownView {
						return err
					}
					g.DeleteKeybindings(v.Name())
					g.DeleteView(v.Name())
					return err
				}
			}
			return nil
		}
		gui.Execute(popup)

		select {
		case c := <-inputChan:
			if c < 1 || c > len(candidate) {
				return nil
			}
			return candidate[c-1]
		case <-done:
		case <-time.After(time.Duration(20) * time.Second):
			reject(gui, nil)
		}
		return nil
	}
}

func selectMsg(accept bool, resp chan<- int) func(*gocui.Gui, *gocui.View) error {

	return func(g *gocui.Gui, v *gocui.View) error {
		popup = nil
		cy := -1
		if accept {
			_, cy = v.Cursor()
		}
		select {
		case resp <- cy:
		case <-time.After(time.Duration(500) * time.Millisecond):
		}
		if _, err := g.SetCurrentView("log"); err != nil {
			return err
		}
		g.DeleteKeybindings("msg")
		if err := g.DeleteView("msg"); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
		}
		return nil
	}
}
