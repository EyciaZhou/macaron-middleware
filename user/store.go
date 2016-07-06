package user
import (
	"regexp"
	"database/sql"
	"crypto/sha256"
	"math/rand"
	"strings"
	"bytes"
	"strconv"
	"github.com/go-sql-driver/mysql"
	"errors"
	"github.com/Sirupsen/logrus"
	"log"
	"time"
)


var (
	ERROR_UNAME_FORMAT = errors.New("用户名格式错误")
	ERROR_USERNAME_FORMAT = errors.New("用户名格式错误")
	ERROR_EMAIL_FORMAT = errors.New("邮箱格式错误")
	ERROR_PASSWORD_FORMAT = errors.New("密码格式错误")
	ERROR_NICKNAME_FORMAT = errors.New("昵称格式错误")

	ERROR_NOT_EXISTED_USER = errors.New("用户不存在")
	ERROR_WRONG_PASSWORD = errors.New("密码错误")
	ERROR_DUPLICATE_USER = errors.New("有重复的用户信息")

	ERROR_SERVER_ERROR = errors.New("数据库错误")

	ERROR_MODIFY_PASSWORD = errors.New("修改密码时错误,修改失败")
	ERROR_MODIFY_NICKNAME = errors.New("修改昵称时错误,修改失败")
	ERROR_NO_PERMISSION = errors.New("升级管理员时错误,没有权限")
)

type UserFullInfo struct {
	UserInfo
	UserPasswordInfo
}

type UserInfo struct {//auto inc id
	Id       string

	Username string
	Email    string
	Master   int //master level 0-9
	Nickname string
	Head     string
}

type UserPasswordInfo struct {
	SaltedPwd []byte
	Salt []byte
}

var Ruler = newRuler()
type ruler struct {
	Username *regexp.Regexp
	Email    *regexp.Regexp
	Uid      *regexp.Regexp
}

func newRuler() *ruler {
	return &ruler{
		Username:regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9_]{4,15}$"), //start with
		Email:regexp.MustCompile(`^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$`),
		Uid:regexp.MustCompile(`^[0-9]+$`),
	}
}

func (*ruler) Pwd_sha256(bs []byte) bool {
	return len(bs) == 32
}

func (*ruler) Nickname(name string) bool {
	return len(name) > 0 && len(name) <= 40
}

func (*ruler) Uname(uname string) bool {
	return Ruler.Username.MatchString(uname) || Ruler.Email.MatchString(uname) || Ruler.Uid.MatchString(uname)
}

func GenSalt() []byte {
	result := make([]byte, 10)
	for i := 0; i < 10; i++ {
		result[i] = (byte)(rand.Uint32() % 256)
	}
	return result[:]
}

func Sha256(bs []byte) []byte {
	hasher := sha256.New()
	hasher.Write(bs)
	return hasher.Sum(nil)
}

//NewSaltPassword:
// 	create a new salt and salt the password hash, return the salted result, and the salt
// 	result in sha256 format
func NewSaltPassword(pwdHash []byte) (saltedPwdSha256 []byte, salt []byte) {
	salt = GenSalt()
	saltedPwdSha256 = SaltPassword(pwdHash, salt)
	return
}

//SaltPassword
//	function to salt the password hash with the salt given, result in sha256 format
func SaltPassword(pwdHash []byte, salt []byte) (saltedPwdSha256 []byte) {
	saltedPwd := append(pwdHash, salt...)
	saltedPwdSha256 = Sha256(saltedPwd)
	return
}

type UserStore interface {
	AddUser(username string, email string, pwdSha256 []byte, nickname string) (string, error)
	VerifyPassword(uname string, challenge []byte) (*UserInfo, error)
	ChangeNickname(uname string, nickname string) error
	ChangeHead(uname string, value string) error
	ChangePassword(uname string, oldPwd []byte, newPwd []byte) error
	GrantMaster(fromUname string, fromPwd []byte, grantToUname string, level int) error
	GetIdFromUname(uname string) (string, error)
	GetUserInfo(uname string) (*UserFullInfo, error)
}

type MysqlStore struct {
	*sql.DB
}

func (db *MysqlStore) GetUserInfo(uname string) (*UserFullInfo, error) {
	if !Ruler.Uname(uname) {
		return nil, ERROR_UNAME_FORMAT
	}
	uname = strings.ToLower(uname)

	row := db.QueryRow(`
		SELECT
				id, username, email, master, pwd, salt, nickname, head
			FROM _user
			WHERE (username=? OR email=? OR id=?)
			LIMIT 1
	`, uname, uname, uname)

	var (
		head sql.NullString
	)
	userinfo := &UserFullInfo{}

	err := row.Scan(&userinfo.Id, &userinfo.Username, &userinfo.Email, &userinfo.Master,
		&userinfo.SaltedPwd, &userinfo.Salt, &userinfo.Nickname, &head)

	if err == sql.ErrNoRows {
		return nil, ERROR_NOT_EXISTED_USER
	} else if err != nil {
		logrus.Error("获取用户时错误", err.Error())
		return nil, ERROR_SERVER_ERROR
	}
	userinfo.Head = head.String

	return userinfo, nil
}

func (db *MysqlStore) VerifyPassword(uname string, challenge []byte) (*UserInfo, error) {
	userinfo, err := db.GetUserInfo(uname)
	if err != nil {
		return nil, err
	}

	if bytes.Compare(SaltPassword(challenge, userinfo.Salt), userinfo.SaltedPwd) != 0 {
		return nil, ERROR_WRONG_PASSWORD
	}

	return &userinfo.UserInfo, nil
}

func (db *MysqlStore) ChangeNickname(uname string, nickname string) error {
	if !Ruler.Uname(uname) {
		return ERROR_UNAME_FORMAT
	}
	uname = strings.ToLower(uname)

	result, err := db.Exec(`
		UPDATE
			_user
		SET
			nickname=?
		WHERE (username=? OR email=? OR id=?)
		LIMIT 1
	`, nickname, uname, uname, uname)

	if err != nil {
		logrus.Error("修改昵称时错误", err.Error())
		return ERROR_SERVER_ERROR
	}

	if rowsCnt, _ := result.RowsAffected(); rowsCnt != 1 {
		return ERROR_MODIFY_NICKNAME
	}
	return nil
}

func (db *MysqlStore) AddUser(username string, email string, pwdSha256 []byte, nickname string) (string, error) {
	if !Ruler.Username.MatchString(username) {
		return "", ERROR_USERNAME_FORMAT
	}
	if !Ruler.Email.MatchString(email) {
		return "", ERROR_EMAIL_FORMAT
	}
	if !Ruler.Pwd_sha256(pwdSha256) {
		return "", ERROR_PASSWORD_FORMAT
	}
	if !Ruler.Nickname(nickname) {
		return "", ERROR_NICKNAME_FORMAT
	}
	username = strings.ToLower(username)
	email = strings.ToLower(email)

	saltedPwdSha256, salt := NewSaltPassword(pwdSha256)

	result, err := db.Exec(`
		INSERT INTO
				_user (username, email, pwd, salt, nickname)
			VALUE
				(?,?,?,?,?)
	`, username, email, saltedPwdSha256, salt, nickname)
	if err != nil {
		if e, ok := err.(*mysql.MySQLError); ok {
			if e.Number == 1062 {
				return "", ERROR_DUPLICATE_USER
			}
		}
		logrus.Error("创建用户时错误", err.Error())
		return "", ERROR_SERVER_ERROR
	}

	id, err := result.LastInsertId()
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(id, 10), nil
}

func (db *MysqlStore) ChangePassword(uname string, oldPwd []byte, newPwd []byte) error {
	userInfo, err := db.VerifyPassword(uname, oldPwd)
	if err != nil {
		return err
	}

	new_salted, salt := NewSaltPassword(newPwd)
	result, err := db.Exec(`
		UPDATE
				_user
			SET
				pwd=?, salt=?
			WHERE
				id=?
	`, new_salted, salt, userInfo.Id)
	if err != nil {
		logrus.Error("修改密码时错误", err.Error())
		return ERROR_SERVER_ERROR
	}

	if rowsCnt, _ := result.RowsAffected(); rowsCnt != 1 {
		return ERROR_MODIFY_PASSWORD
	}

	return nil
}

func (db *MysqlStore) GetIdFromUname(uname string) (string, error) {
	if !Ruler.Uname(uname) {
		return "", ERROR_UNAME_FORMAT
	}
	uname = strings.ToLower(uname)

	row := db.QueryRow(`
		SELECT
				id
			FROM _user
			WHERE (username=? OR email=? OR id=?)
			LIMIT 1
	`, uname, uname, uname)

	var id string
	if err := row.Scan(&id); err != nil {
		logrus.Error("获取id时错误", err.Error())
		return "", ERROR_SERVER_ERROR
	}
	return id, nil
}

func (db *MysqlStore) ChangeHead(uname string, value string) error {
	if !Ruler.Uname(uname) {
		return ERROR_UNAME_FORMAT
	}
	uname = strings.ToLower(uname)

	_, err := db.Exec(`UPDATE _user
				SET head=?
				WHERE (username=? OR email=? OR id=?)`, value, uname, uname, uname)
	return err
}

func (db *MysqlStore) GrantMaster(fromUname string, fromPwd []byte, grantToUname string, level int) error {
	if !Ruler.Uname(grantToUname) {
		return ERROR_UNAME_FORMAT
	}
	grantToUname = strings.ToLower(grantToUname)

	FromUserInfo, err := db.VerifyPassword(fromUname, fromPwd)
	if err != nil {
		return err
	}

	result, err := db.Exec(`
		UPDATE
			_user
		SET
			master=?
		WHERE EXISTS (
			SELECT * FROM
				_usr
			WHERE
				id=? AND master > ?
		) AND (username=? OR email=? OR id=?)
	`, level, FromUserInfo.Id, level, grantToUname)
	if err != nil {
		logrus.Error("升级管理员时错误", err.Error())
		return ERROR_SERVER_ERROR
	}

	if cnt, _ := result.RowsAffected(); cnt != 1 {
		return ERROR_NO_PERMISSION
	}
	return nil
}

func init() {
	rand.Seed(time.Now().UnixNano())

	RegisterStore("mysql", func(dialString string, log *log.Logger) (UserStore) {
		db, err := sql.Open("mysql", dialString)
		if err != nil {
			log.Panic("M.msghub Can't Connect DB REASON : " + err.Error())
		}
		err = db.Ping()
		if err != nil {
			log.Panic("M.msghub Can't Connect DB REASON : " + err.Error())
		}
		log.Println("M.msghub connected")

		return &MysqlStore{db}
	})
}