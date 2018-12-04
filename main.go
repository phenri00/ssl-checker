package main

import (
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "github.com/coreos/go-systemd/login1"
    "io/ioutil"
    "log"
    "math"
    "os/exec"
    "strings"
    "time"
)

const (
    //days left to start notify
    numDays     = 30
    certPath    = ""
    certName    = ""
    notifyTitle = "Wifi certificate"
)

func main() {

    users := currentUsers()

    for _, user := range users {
        //filter non-relative users
        if !(user.Name == "gdm" || user.Name == "lightdm" || user.Name == "root") {
            path := fmt.Sprintf(`%s/%s/%s`, certPath, user.Name, certName)

            days, valid, err := parseCert(path)

            if err == nil {
                if !valid {
                    message := "Wifi certificate has expired."
                    err := showNotify(notifyTitle, message, user.Name, user.UID)
                    if err != nil {
                        log.Println(err)
                    }
                } else if numDays > days {
                    message := fmt.Sprintf("Wifi certificate will expire in: %d days ", days)
                    err := showNotify(notifyTitle, message, user.Name, user.UID)
                    if err != nil {
                        log.Println(err)
                    }
                }
                log.Println("Name: ", user.Name+" UID: ", user.UID, " Days: ", days, " Valid: ", valid)
            } else {
                log.Println("user:"+user.Name+" err:", err)
            }
        }
    }
}

func parseCert(path string) (int, bool, error) {

    t := time.Now().UTC()

    f, err := ioutil.ReadFile(path)
    if err != nil {
        return 0, false, errors.New("Unable to read file")
    }

    //if exists returns a remainder, but we will only handle first block found.
    block, _ := pem.Decode(f)

    if block == nil || block.Type != "CERTIFICATE" {
        log.Fatal("failed to parse certificate PEM")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatal("failed to parse certificate")
    }

    remainingDays := int(cert.NotAfter.Sub(t).Hours() / 24)
    valid := !math.Signbit(float64(remainingDays))

    return remainingDays, valid, nil
}

func currentUsers() []login1.User {

    con, err := login1.New()
    if err != nil {
        log.Println(err)
    }

    currentUsers, err := con.ListUsers()
    if err != nil {
        log.Println(err)
    }

    return currentUsers
}

func showNotify(title string, message string, username string, uid uint32) error {

    dbusAddress := getDbusAddress(uid)

    cmd := fmt.Sprintf(`%s /usr/bin/notify-send "%s" "%s" -u critical`, dbusAddress, title, message)

    c := exec.Command("/bin/su", username, "-c", cmd)

    return c.Run()
}

func getDbusAddress(uid uint32) string {
    //Try to read dbus-session file if exists
    path := fmt.Sprintf("/run/user/%d/dbus-session", uid)
    f, err := ioutil.ReadFile(path)
    if err != nil {
        //return default dbus address in 18.04
        return fmt.Sprintf(`DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus`, uid)
    }
    return strings.TrimSuffix(fmt.Sprintf("%s", f), "\n")
}
