package services

import (
	"errors"
	"fmt"

	"git.difuse.io/Difuse/kalmia/db/models"
	"gorm.io/gorm"
)

func (service *DocService) GetPages() ([]models.Page, string, error) {
	var pages []models.Page

	if err := service.DB.Preload("Author", func(db *gorm.DB) *gorm.DB {
		return service.DB.Select("ID", "Username", "Email", "Photo")
	}).Preload("Editors", func(db *gorm.DB) *gorm.DB {
		return service.DB.Select("users.ID", "users.Username", "users.Email", "users.Photo")
	}).Select("ID", "Title", "Slug", "DocumentationID", "PageGroupID", "Order", "CreatedAt", "UpdatedAt", "AuthorID", "LastEditorID", "IsIntroPage", "IsPage").
		Find(&pages).Error; err != nil {
		return nil, "failed_to_get_pages", err
	}

	return pages, "", nil
}

func (service *DocService) GetPage(id uint) (models.Page, string, error) {
	var page models.Page

	if err := service.DB.Preload("Author", func(db *gorm.DB) *gorm.DB {
		return service.DB.Select("ID", "Username", "Email", "Photo")
	}).Preload("Editors", func(db *gorm.DB) *gorm.DB {
		return service.DB.Select("users.ID", "users.Username", "users.Email", "users.Photo")
	}).First(&page, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.Page{}, "page_not_found", err
		} else {
			return models.Page{}, "failed_to_get_page", err
		}
	}

	return page, "", nil
}

func (service *DocService) CreatePage(page *models.Page) (string, error) {
	if err := service.DB.Create(&page).Error; err != nil {
		return "failed_to_create_page", err
	}

	docId, err := service.GetDocumentationIDOfPage(page.ID)

	if err != nil {
		return "failed_to_get_documentation_id", err
	}

	parentDocId, _ := service.GetRootParentID(docId)

	if parentDocId == 0 {
		err = service.AddBuildTrigger(docId)
	} else {
		err = service.AddBuildTrigger(parentDocId)
	}

	if err != nil {
		return "failed_to_update_write_build", err
	}

	return "", nil
}

func (service *DocService) EditPage(user models.User, id uint, title, slug, content string, order *uint, pageGroupId *uint) (string, error) {
	tx := service.DB.Begin()

	var page models.Page
	if err := tx.Preload("Editors").First(&page, id).Error; err != nil {
		tx.Rollback()
		return "page_not_found", err
	}

	page.Title = title
	page.Slug = slug

	if content != "" {
		page.Content = content
	}

	page.LastEditorID = &user.ID
	if order != nil {
		page.Order = order
	}

	if pageGroupId != nil {
		page.PageGroupID = pageGroupId
	}

	alreadyEditor := false
	for _, editor := range page.Editors {
		if editor.ID == user.ID {
			alreadyEditor = true
			break
		}
	}

	if !alreadyEditor {
		page.Editors = append(page.Editors, user)
	}

	if err := tx.Save(&page).Error; err != nil {
		tx.Rollback()
		return "failed_to_update_page", err
	}

	if err := tx.Commit().Error; err != nil {
		return "failed_to_commit_changes", err
	}

	docId, err := service.GetDocumentationIDOfPage(id)

	if err != nil {
		return "failed_to_get_documentation_id", err
	}

	parentDocId, _ := service.GetRootParentID(docId)

	if parentDocId == 0 {
		err = service.AddBuildTrigger(docId)
	} else {
		err = service.AddBuildTrigger(parentDocId)
	}

	if err != nil {
		return "failed_to_update_write_build", err
	}

	return "", nil
}

func (service *DocService) DeletePage(id uint) (string, error) {
	docId, err := service.GetDocumentationIDOfPage(id)

	tx := service.DB.Begin()
	if tx.Error != nil {
		return "failed_to_start_transaction", err
	}

	var page models.Page
	if err := tx.First(&page, id).Error; err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "page_not_found", err
		}
		return "failed_to_fetch_page", err
	}

	if err := tx.Model(&page).Association("Editors").Clear(); err != nil {
		tx.Rollback()
		return "failed_to_clear_page_associations", err
	}

	if err := tx.Delete(&page).Error; err != nil {
		tx.Rollback()
		return "failed_to_delete_page", err
	}

	if err := tx.Commit().Error; err != nil {
		return "transaction_commit_failed", err
	}

	if err != nil {
		return "failed_to_get_documentation_id", err
	}

	parentDocId, _ := service.GetRootParentID(docId)

	if parentDocId == 0 {
		err = service.AddBuildTrigger(docId)
	} else {
		err = service.AddBuildTrigger(parentDocId)
	}

	if err != nil {
		return "failed_to_update_write_build", err
	}

	return "", nil
}

func (service *DocService) ReorderPage(id uint, pageGroupID *uint, order *uint) (string, error) {
	var page models.Page
	if err := service.DB.First(&page, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "page_not_found", err
		}
		return "failed_to_fetch_page", err
	}

	page.PageGroupID = pageGroupID
	page.Order = order

	if err := service.DB.Save(&page).Error; err != nil {
		return "failed_to_update_page", err
	}

	docId, err := service.GetDocumentationIDOfPage(id)

	if err != nil {
		return "failed_to_get_documentation_id", err
	}

	parentDocId, _ := service.GetRootParentID(docId)

	if parentDocId == 0 {
		err = service.AddBuildTrigger(docId)
	} else {
		err = service.AddBuildTrigger(parentDocId)
	}

	if err != nil {
		return "failed_to_update_write_build", err
	}

	return "", nil
}

func (service *DocService) GetDocumentationIDOfPage(id uint) (uint, error) {
	var page models.Page
	if err := service.DB.First(&page, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, fmt.Errorf("page_not_found: %v", err)
		}
		return 0, fmt.Errorf("failed_to_fetch_page: %v", err)
	}

	return page.DocumentationID, nil
}

func (service *DocService) GetPagesOfPageGroup(id uint) ([]models.Page, error) {
	var pages []models.Page

	if err := service.DB.Where("page_group_id = ?", id).Find(&pages).Error; err != nil {
		return nil, fmt.Errorf("failed_to_get_pages: %v", err)
	}

	return pages, nil
}
