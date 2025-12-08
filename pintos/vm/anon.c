/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/vaddr.h"
#include <string.h>
#include <bitmap.h>

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

static struct bitmap *swap_bitmap; 
static struct lock swap_lock;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get (1, 1);
	
	// 디스크 크기에 맞춰 비트맵 생성 (페이지 단위)
    size_t swap_size = disk_size(swap_disk) / (PGSIZE / DISK_SECTOR_SIZE);
    swap_bitmap = bitmap_create(swap_size);
    
    lock_init (&swap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	// Set up the handler
	page->operations = &anon_ops;
    struct anon_page *anon_page = &page->anon;
    
    // 초기 상태는 스왑 디스크에 없음 (-1)
    anon_page->swap_index = -1;

    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page UNUSED = &page->anon;
    
	if((anon_page->swap_index == -1)){
		memset(kva, 0, PGSIZE);
		return true;
	}

	// 비트맵 범위 검사
    if (!bitmap_contains(swap_bitmap, anon_page->swap_index, 1, false)) {
        // 이미 사용 중이지 않은 인덱스(false)를 접근하려 하면 에러? 
        // 혹은 범위 체크
        return false;
    }

	disk_sector_t sec_no = anon_page->swap_index * (PGSIZE / DISK_SECTOR_SIZE);	

	for (int i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
        disk_read(swap_disk, sec_no + i, kva + i * DISK_SECTOR_SIZE);
    }

	lock_acquire(&swap_lock);
    bitmap_set(swap_bitmap, anon_page->swap_index, false);
    lock_release(&swap_lock);
    
    anon_page->swap_index = -1;
	
    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page UNUSED = &page->anon;

	if (page->frame == NULL) return false;

	// 빈 슬롯 찾기 (비트맵 스캔)
    lock_acquire(&swap_lock);
    // false(빈 공간)인 비트를 찾아서 true(사용 중)로 뒤집음
    size_t swap_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    lock_release(&swap_lock);

    if (swap_index == BITMAP_ERROR) {
        return false; // 스왑 공간 꽉 참
    }

    // 디스크 쓰기
    disk_sector_t sec_no = swap_index * (PGSIZE / DISK_SECTOR_SIZE);
    
    for (int i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
        disk_write(swap_disk, sec_no + i, page->frame->kva + i * DISK_SECTOR_SIZE);
    }
 
    //인덱스 저장
    anon_page->swap_index = swap_index;
    
    // 페이지는 이제 메모리에서 해제될 것이므로 연결 끊기 (호출자가 함)
    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page UNUSED = &page->anon;
		
	// 스왑 슬롯을 점유하고 있다면 해제
    if (anon_page->swap_index != -1) {
        lock_acquire(&swap_lock);
        bitmap_set(swap_bitmap, anon_page->swap_index, false);
        lock_release(&swap_lock);
        anon_page->swap_index = -1;
    }
}
