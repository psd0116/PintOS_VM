/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "userprog/syscall.h"
#include <bitmap.h>

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	// mmap 정보를 담을 구조체
	struct file_page *file_page UNUSED = &page->file;
	struct aux_info *aux_info = (struct aux_info *)page->uninit.aux;

	file_page->file = aux_info->file;
    file_page->ofs = aux_info->ofs;
    file_page->read_bytes = aux_info->read_bytes;
    file_page->zero_bytes = aux_info->zero_bytes;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	
	// 파일에서 다시 읽어오면 됨
    bool lock_held = lock_held_by_current_thread(&filesys_lock);
    if (!lock_held) lock_acquire(&filesys_lock);

    // 파일 위치 이동 후 읽기
    // file_read_at을 쓰면 seek 없이 안전하게 읽을 수 있음
    if (file_read_at(file_page->file, kva, 
                     file_page->read_bytes, file_page->ofs) != (int)file_page->read_bytes) {
        if (!lock_held) lock_release(&filesys_lock);
        return false;
    }

    // 남은 공간 0으로 초기화
    memset(kva + file_page->read_bytes, 0, file_page->zero_bytes);
    
    if (!lock_held) lock_release(&filesys_lock);
    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	// Dirty Bit 확인 (수정되었는가?)
    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        
        bool lock_held = lock_held_by_current_thread(&filesys_lock);
        if (!lock_held) lock_acquire(&filesys_lock);

        // 수정되었다면 파일에 저장 (Write-back)
        file_write_at(file_page->file, page->frame->kva, 
                      file_page->read_bytes, file_page->ofs);

        // Dirty Bit 해제 (저장했으니 이제 깨끗함)
        pml4_set_dirty(thread_current()->pml4, page->va, false);
        
        if (!lock_held) lock_release(&filesys_lock);
    }
    
    // 메모리 해제는 호출자(vm_evict_frame)가 수행
    // 파일 페이지는 그냥 버리면 됨 (나중에 파일에서 다시 읽으면 되니까)
    page->frame = NULL;

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	// Dirty Bit 확인 후 파일 저장 (Munmap 시 필수)
    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        bool lock_held = lock_held_by_current_thread(&filesys_lock);
        if (!lock_held) lock_acquire(&filesys_lock);
        
        file_write_at(file_page->file, page->frame->kva, 
                      file_page->read_bytes, file_page->ofs);
                      
        if (!lock_held) lock_release(&filesys_lock);
    }

    // 파일 닫기
    if (file_page->file != NULL) {
        bool lock_held = lock_held_by_current_thread(&filesys_lock);
        if (!lock_held) lock_acquire(&filesys_lock);
        file_close(file_page->file);
        if (!lock_held) lock_release(&filesys_lock);
    }
}

static bool lazy_load_file (struct page *page, void *aux) {
    struct aux_info *info = (struct aux_info *)aux;

	page->operations = &file_ops;
	bool lock_held = lock_held_by_current_thread(&filesys_lock);
    if (!lock_held) lock_acquire(&filesys_lock);
	
	if (info->file == NULL) {
		if (!lock_held) lock_release(&filesys_lock);
		free(info);
		return false;
	}

    // 파일 읽기 (Load)
    file_seek(info->file, info->ofs);
    if (file_read(info->file, page->frame->kva, info->read_bytes) != info->read_bytes) {
		if (!lock_held) lock_release(&filesys_lock); // 실패 시 해제
		free(info);
		return false; // 읽기 실패
    }

    // 0으로 채우기
    memset(page->frame->kva + info->read_bytes, 0, info->zero_bytes);
	if (!lock_held) lock_release(&filesys_lock); // 성공 시 해제

	struct file_page *file_page = &page->file;
    file_page->file = info->file;
    file_page->ofs = info->ofs;
    file_page->read_bytes = info->read_bytes;
    file_page->zero_bytes = info->zero_bytes;
	file_page->swap_index = -1;  // 초기화

    free(info);
    return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {

	if (length == 0) return NULL;

    struct file *reopen_file = file_reopen(file);
    if (reopen_file == NULL) return NULL;

    void *start_addr = addr; // 반환할 시작 주소 저장
	bool lock_held = lock_held_by_current_thread(&filesys_lock);
	if (!lock_held) lock_acquire(&filesys_lock);
    size_t file_len = file_length(reopen_file);
	if (!lock_held) lock_release(&filesys_lock);

    // length가 0이 될 때까지 반복
    while (length > 0) {
        size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
        
        // 파일 끝을 넘어가는 경우 처리
		if (offset >= file_len) {
			page_read_bytes = 0;
			page_zero_bytes = PGSIZE;
		} else if (offset + page_read_bytes > file_len) {
			page_read_bytes = file_len - offset;
			page_zero_bytes = PGSIZE - page_read_bytes;
		}

        struct aux_info *info = malloc(sizeof(struct aux_info));
        if (info == NULL) {
            file_close(reopen_file);
            return NULL;
        }

		info->file = file_reopen(file);
		if (info->file == NULL) {
			free(info);
			file_close(reopen_file);
			return NULL;
		}
		
		info->ofs = offset;
		info->read_bytes = page_read_bytes;
		info->zero_bytes = page_zero_bytes;

        // 페이지 예약 (VM_FILE 타입)
        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_file, info)){
            file_close(info->file);
            free(info);
            file_close(reopen_file);
            return NULL;
        }

        // 다음 페이지로 이동
		addr += PGSIZE;
		offset += page_read_bytes;  /* 읽은 바이트만 증가 */
		length -= page_read_bytes;   /* length도 읽은 바이트만 감소 */
    }
    
    // 원본 reopen_file은 이제 필요 없음 (각 페이지가 복사본 가짐)
    file_close(reopen_file);
    return start_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct thread *cur = thread_current();
	while (true) {
        struct page *page = spt_find_page(&cur->spt, addr);
        if (page == NULL) break;

        spt_remove_page(&cur->spt, page);

        addr += PGSIZE;
    }
}