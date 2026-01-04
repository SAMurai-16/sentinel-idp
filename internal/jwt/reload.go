package jwtutil

import (
	"database/sql"
	
)

func (km *KeyManager) ReloadFromDB(db *sql.DB) error {
	newKM, err := LoadKeys(db)
	if err != nil {
		return err
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	km.privateKeys = newKM.privateKeys
	km.publicKeys = newKM.publicKeys
	km.activeKID = newKM.activeKID

	return nil
}
