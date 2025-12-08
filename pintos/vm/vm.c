/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <hash.h>
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include <string.h>

struct list frame_table;
struct lock frame_table_lock;

void spt_destroy_page (struct hash_elem *e, void *aux);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();

#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
	lock_init(&frame_table_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT);

	struct supplemental_page_table *spt = &thread_current ()->spt;

	ASSERT (pg_ofs (upage) == 0);

	if (spt_find_page (spt, upage) == NULL) {
		struct page *page = malloc (sizeof (struct page));
		if (page == NULL)
			goto err;

		bool (*page_initializer) (struct page *, enum vm_type, void *) = NULL;
		switch (VM_TYPE (type)) {
		case VM_ANON:
			page_initializer = anon_initializer;
			break;
		case VM_FILE:
			page_initializer = file_backed_initializer;
			break;
		default:
			goto err;
		}

		uninit_new (page, upage, init, type, aux, page_initializer);
		page->writable = writable;
		page->thread = thread_current ();

		if (spt_insert_page (spt, page))
			return true;
		free (page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	// 더미 페이지 생성
	struct page page;
	// 4kb로 정렬 -> 가상 주소를 찾아야 하기 때문
	page.va = pg_round_down(va); // 내림
	// 테이블 검색
	struct hash_elem *e = hash_find(&spt->page, &page.hash_elem);
	if(e == NULL) return NULL;
	// page 구조체로 hash_elem을 준다.
	return hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	int succ = false;
	succ = hash_insert(&spt->page, &page->hash_elem) == NULL;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	// hash 테이블에서 삭제하기
	struct hash_elem *e;

	e = hash_delete (&spt->page, &page->hash_elem);
	// 페이지 메모리 삭제하기
	if(e != NULL) spt_destroy_page (e, NULL);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	struct thread *cur = thread_current();
	
	if (list_empty(&frame_table)) return NULL;

	struct list_elem *e = NULL;
	
	if (e == NULL || e == list_end(&frame_table)) {
        e = list_begin(&frame_table);
    }

	struct list_elem *start = e;

	while (true) {
		if (e == list_end(&frame_table)) {
			e = list_begin(&frame_table);
		}
		
		struct frame *f = list_entry(e, struct frame, frame_elem);

		// 프레임에 연결된 페이지가 없으면 스킵
        if (f->page == NULL) {
            e = list_next(e);
            /* 한 바퀴 다 돌아서 다시 제자리로 온 경우 방지 */
            if (e == start) break; 
            continue;
        }
		struct thread *owner = f->page->thread;
		uint64_t *owner_pml4 = owner->pml4; // 혹은 f->owner->pml4; (구현에 따라 다름)
		
		if (pml4_is_accessed(owner_pml4, f->page->va)) {
            /* 참조 비트가 1이면(최근 사용됨), 0으로 내리고 다음 기회 부여 (Second Chance) */
            pml4_set_accessed(owner_pml4, f->page->va, false);
        } else {
            /* 참조 비트가 0이면 희생자로 선정 */
            victim = f;
            e = list_next(e); // 다음 검색을 위해 이동해놓고 리턴
            return victim;
        }
		e = list_next(e);
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if (victim == NULL) return NULL;
	
	struct page *page = victim->page;
	if (page == NULL) return NULL;

	// swap_out 실패시 NULL반환
	if(!swap_out(page)) return NULL;

	struct thread *owner = page->thread;

	pml4_clear_page(owner->pml4, page->va);

	page->frame = NULL;
	victim->page = NULL;

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	void *kva = palloc_get_page (PAL_USER | PAL_ZERO);
	/* TODO: Fill this function. */
	struct frame *frame = NULL;
	
	if (kva == NULL){
		struct frame *victim = vm_evict_frame();
		if (victim == NULL) {
			return NULL;
		}
		
		memset(victim->kva, 0, PGSIZE);

		victim->page = NULL;  // ← 명시적으로 초기화
		ASSERT(victim->kva != NULL);
		ASSERT(victim->page == NULL);

		return victim; // 이미 frame_table에 있삼
	}
	
	// 프레임 맴버 초기화
	frame = malloc(sizeof(struct frame));
	if (frame == NULL) {
        palloc_free_page(kva);
        return NULL;
    }

	frame->kva = kva;
	frame->page = NULL;

	lock_acquire (&frame_table_lock);
	list_push_back (&frame_table, &frame->frame_elem);
	lock_release (&frame_table_lock);

	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr UNUSED) {
	void *stack_bottom = pg_round_down (addr);
    // alloc만 수행하기
	if (vm_alloc_page(VM_ANON| VM_MARKER_0, stack_bottom, true)) {
		return vm_claim_page(stack_bottom);
	}

	return false;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct thread *cur = thread_current();
	struct supplemental_page_table *spt = &cur->spt;
	struct page *page;

	// 커널 영역 주소이거나 주소가 NULL이면 처리 불가
	if (is_kernel_vaddr(addr) || addr == NULL) {
		return false;
    }
	
	page = spt_find_page (spt, addr);
	
	// 스택 확장 판별 / 접근 주소가 USER_STACK인가? / 접근 주소가 1MB 제한 이내인가? /
	if (page == NULL && addr <= (void *)USER_STACK && addr >= (void *)(USER_STACK - (1 << 20))) {
        // 스택 포인터 검증 (User vs Kernel 모드에 따라 rsp 결정)
        uintptr_t rsp = user ? f->rsp : cur->stack_pointer;
        if (addr >= (void *)(rsp - 8)) {
			if (vm_stack_growth(addr)) {
                return true;
            }
            return false;
        }
    }
	
	// 페이지가 없으면 에러
	if (page == NULL) return false;
	
	if (write && !page->writable) {
        return false; 
    }

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
	// 해당 va를 가진 페이지 구조체 찾기
	page = spt_find_page(&thread_current()->spt, va);
	
	// 페이지가 없으면 실패
	if(page == NULL) return false;
	
	return vm_do_claim_page (page);
}

static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	// 프레임 할당 받기
	struct frame *frame = vm_get_frame ();
	struct thread *t = thread_current ();
	if (frame == NULL) return false;

	/* Set links */
	// 링크하기
	frame->page = page;
	page->frame = frame;

	if (!install_page(page->va, frame->kva, page->writable)) {
		frame->page = NULL;
		page->frame = NULL;
		return false;
	}
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// MMU 설정하기 -> 현재 스레드, 가상주소, 커널 가상주소, 쓰기 권한
	// 매핑 실패시
	if (!swap_in(page, frame->kva)) {
		/* swap_in 실패 시 페이지 테이블 엔트리 제거 */
		pml4_clear_page(t->pml4, page->va);
		frame->page = NULL;
		page->frame = NULL;
		return false;
	}

	return true;
}

// hash_hash_func
// 2개의 포인터를 넘겨야 함.
unsigned page_hash (const struct hash_elem *h, void *aux UNUSED){
	const struct page *p = hash_entry(h, struct page, hash_elem); // hash_elem을 사용해서 struct page를 찾아낸다.
	return hash_bytes (&p->va, sizeof p->va); // va를 해싱한다.1
}

// 버킷 리스트 정렬용 크기 비교 함수
bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
	const struct page *a_ = hash_entry(a, struct page, hash_elem);
	const struct page *b_ = hash_entry(b, struct page, hash_elem);
	if (a_->va < b_->va) return true;
	return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	// 해시테이블 초기화
	hash_init (&spt->page, page_hash, page_less, NULL);
}

bool
lazy_load_segment (struct page *page, void *aux) {
    /* 1. aux 정보를 가져옴 */
    struct aux_info *info = (struct aux_info *)aux;
    
    /* 파일이 닫혀있거나 잘못된 경우 방지 */
    if (info->file == NULL) {
        free(info);
        return false;
    }

    /* 2. 파일 위치 이동 (Seek) */
    /* 파일 시스템 접근 시 경쟁 상태 방지를 위해 락이 필요할 수 있음 */
    // lock_acquire(&filesys_lock); 
    file_seek(info->file, info->ofs);
    
    /* 3. 데이터 읽기 (Read) */
    /* page->frame->kva는 커널 가상 주소(물리 메모리와 매핑됨) */
    off_t read_bytes = file_read(info->file, page->frame->kva, info->read_bytes);
    // lock_release(&filesys_lock);

    /* 읽은 바이트 수가 예상과 다르면 실패 처리 */
    if (read_bytes != (off_t)info->read_bytes) {
        free(info); // 실패해도 메모리는 해제해야 함
        return false; 
    }

    /* 4. 나머지 공간 0으로 채우기 (Zeroing) */
    /* bss 영역이나 페이지 남은 공간 처리 */
    memset(page->frame->kva + read_bytes, 0, info->zero_bytes);

    /* 5. aux 메모리 해제 */
    /* 페이지 로딩이 끝났으므로 aux 정보는 더 이상 필요 없음 */
    /* 주의: info->file은 닫지 않음 (mmap 등에서 계속 쓸 수 있으므로) */
    free(info); 

    return true;
}

// UNINIT 페이지 복사
static bool
copy_uninit_page(struct supplemental_page_table *dst, struct page *src_page, void *upage, bool writable) {
	
	enum vm_type type = VM_TYPE(page_get_type(src_page));
    vm_initializer *init = NULL;
    void *aux = NULL;

if (type == VM_FILE) {
        /* 자식에게 줄 새로운 aux 할당 */
        struct aux_info *dst_aux = malloc(sizeof(struct aux_info));
        if (dst_aux == NULL) return false;

        /* 소스 정보 추출: 이미 로딩된 페이지(VM_FILE) vs 아직 로딩 안된 페이지(VM_UNINIT) */
        struct file *src_file = NULL;
        off_t src_ofs = 0;
        size_t src_read = 0;
        size_t src_zero = 0;

        if (src_page->operations->type == VM_UNINIT) {
            /* 아직 로딩 안 됨 -> uninit 구조체에서 가져옴 */
            struct aux_info *src_aux = (struct aux_info *)src_page->uninit.aux;
            src_file = src_aux->file;
            src_ofs = src_aux->ofs;
            src_read = src_aux->read_bytes;
            src_zero = src_aux->zero_bytes;
            init = src_page->uninit.init;
        } else {
            /* 이미 로딩 됨 -> file 구조체에서 가져옴 */
            src_file = src_page->file.file;
            src_ofs = src_page->file.ofs;
            src_read = src_page->file.read_bytes;
            src_zero = src_page->file.zero_bytes;
            init = lazy_load_segment; // 혹은 지정된 로더 함수
        }

        // lock_acquire(&filesys_lock); // 필요 시 주석 해제 (호출자가 잡고 있는지 확인 필요)
        dst_aux->file = file_reopen(src_file);
        // lock_release(&filesys_lock);

        if (dst_aux->file == NULL) {
            free(dst_aux);
            return false;
        }

        dst_aux->ofs = src_ofs;
        dst_aux->read_bytes = src_read;
        dst_aux->zero_bytes = src_zero;

        /* 자식 페이지 생성 (UNINIT 상태로) */
        if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, init, dst_aux)) {
            file_close(dst_aux->file); // 실패 시 파일 닫기
            free(dst_aux);
            return false;
        }
    } 
    /* ANON UNINIT 페이지 처리 */
    else {
        // aux나 init이 필요한 경우 여기서 복사 (보통은 NULL)
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, src_page->uninit.init, src_page->uninit.aux)) {
            return false;
        }
    }
    
    return true;
}

// PRESENT 페이지 복사
static bool
copy_present_page(struct supplemental_page_table *dst, struct page *src_page, void *upage, bool writable) {
    
    /* 1. 부모 페이지가 메모리에 있는지 확인 (Swap Out 상태 대비) */
    if (src_page->frame == NULL) {
        if (!vm_claim_page(src_page->va)) {
            return false;
        }
    }
    
    /* 2. 자식에게 새 페이지 할당 (VM_ANON) */
    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, NULL, NULL)) {
        return false;
    }

    /* 3. 자식 페이지 물리 프레임 매핑 (Claim) */
    if (!vm_claim_page(upage)) {
        return false;
    }

    /* 4. 내용 복사 (Deep Copy) */
    struct page *dst_page = spt_find_page(dst, upage);
    
    // 방어 코드
    if (dst_page == NULL || dst_page->frame == NULL) {
        return false;
    }

    /* 부모의 물리 메모리 내용을 자식에게 복사 */
    memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);

    return true;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy(struct supplemental_page_table *dst, struct supplemental_page_table *src) {
    struct hash_iterator i;
    hash_first(&i, &src->page);

    while (hash_next(&i)) {
        struct hash_elem *e = hash_cur(&i);
        struct page *src_page = hash_entry(e, struct page, hash_elem);
        enum vm_type type = VM_TYPE(src_page->operations->type);
		
        void *upage = src_page->va;
        bool writable = src_page->writable;

        if (type == VM_UNINIT) {
            if (!copy_uninit_page(dst, src_page, upage, writable))
                return false;
        } else if (type == VM_ANON) {
            // ANON 페이지만 복사
            if (!copy_present_page(dst, src_page, upage, writable))
                return false;
        } else if (type == VM_FILE) {
            // FILE-BACKED 페이지도 UNINIT로 복사
            // (부모의 초기 상태를 복사)
            if (!copy_uninit_page(dst, src_page, upage, writable))
                return false;
        }
    }
    return true;
}

// 해시 테이블의 각 요소를 삭제할 때 호출될 함수
void
spt_destroy_page (struct hash_elem *e, void *aux UNUSED) {
    struct page *page = hash_entry(e, struct page, hash_elem);
    struct thread *cur = thread_current();

    if (page->frame != NULL) {

        /* 1-1. 프레임 테이블 리스트에서 제거 */
        lock_acquire(&frame_table_lock);
        list_remove(&page->frame->frame_elem);
        lock_release(&frame_table_lock);

        /* 1-2. 페이지 테이블(MMU) 매핑 끊기 */
        /* pml4_clear_page는 present bit를 0으로 만듦 */
        pml4_clear_page(cur->pml4, page->va);
        
        /* 1-3. 물리 메모리 반환 (palloc) */
        /* 이 시점 이후로 kva에 접근하면 커널 패닉 발생 가능 */
        palloc_free_page(page->frame->kva);
        
        /* 1-4. 프레임 구조체 해제 */
        free(page->frame);
        
        /* 안전을 위해 NULL 처리 */
        page->frame = NULL;
    }

    /* 2. 페이지 타입별 정리 (Swap Slot 해제, 파일 닫기 등) */
    /* destroy 매크로가 page->operations->destroy를 호출함 */
    /* 예: anon_destroy에서는 swap_bitmap의 비트를 0으로 바꿔줘야 함 */
    destroy(page);

    /* 3. 페이지 구조체 자체(메타데이터) 해제 */
    free(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_destroy(&spt->page, spt_destroy_page);
}