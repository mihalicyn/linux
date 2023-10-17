// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Christian Brauner <brauner@kernel.org> */

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

#include "internal.h"

/*
 * Outside of this file vfs{g,u}id_t are always created from k{g,u}id_t,
 * never from raw values. These are just internal helpers.
 */
#define VFSUIDT_INIT_RAW(val) (vfsuid_t){ .uid_val = val }
#define VFSGIDT_INIT_RAW(val) (vfsgid_t){ .gid_val = val }

struct mnt_idmap {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	refcount_t count;
	/*
	 * Used only for idmapped mount attached to an isolated user namespace, aka
	 * "isolated mount".
	 *
	 * MUST be zero for any other cases.
	 */
	u32 userns_id;
};

/*
 * Carries the initial idmapping of 0:0:4294967295 which is an identity
 * mapping. This means that {g,u}id 0 is mapped to {g,u}id 0, {g,u}id 1 is
 * mapped to {g,u}id 1, [...], {g,u}id 1000 to {g,u}id 1000, [...].
 */
struct mnt_idmap nop_mnt_idmap = {
	.count	= REFCOUNT_INIT(1),
};
EXPORT_SYMBOL_GPL(nop_mnt_idmap);

/**
 * initial_idmapping - check whether this is the initial mapping
 * @ns: idmapping to check
 *
 * Check whether this is the initial mapping, mapping 0 to 0, 1 to 1,
 * [...], 1000 to 1000 [...].
 *
 * Return: true if this is the initial mapping, false if not.
 */
static inline bool initial_idmapping(const struct user_namespace *ns)
{
	return ns == &init_user_ns;
}

/**
 * make_vfsuid - map a filesystem kuid according to an idmapping
 * @idmap: the mount's idmapping
 * @fs_userns: the filesystem's idmapping
 * @kuid : kuid to be mapped
 *
 * Take a @kuid and remap it from @fs_userns into @idmap. Use this
 * function when preparing a @kuid to be reported to userspace.
 *
 * If initial_idmapping() determines that this is not an idmapped mount
 * we can simply return @kuid unchanged.
 * If initial_idmapping() tells us that the filesystem is not mounted with an
 * idmapping we know the value of @kuid won't change when calling
 * from_kuid() so we can simply retrieve the value via __kuid_val()
 * directly.
 *
 * Return: @kuid mapped according to @idmap.
 * If @kuid has no mapping in either @idmap or @fs_userns INVALID_UID is
 * returned.
 */

vfsuid_t make_vfsuid(struct mnt_idmap *idmap,
		     struct user_namespace *fs_userns,
		     kuid_t kuid)
{
	bool isolated = false;
	u32 mnt_userns_id = idmap->userns_id;
	uid_t uid;
	u32 down_uid;
	u32 res_uid;

	struct user_namespace *ns = NULL;

	if (idmap == &nop_mnt_idmap)
		return VFSUIDT_INIT(kuid);
	if (initial_idmapping(fs_userns))
		uid = __kuid_host_uid(kuid);
	else
		uid = from_kuid(fs_userns, kuid);
	if (uid == (uid_t)-1)
		return INVALID_VFSUID;

	down_uid = map_id_down(&idmap->uid_map, uid);

	/*
	 * Ok, we have failed to map ID down in accordance with
	 * mount's idmapping (in a classical meaning!), but if mount's idmapping was
	 * created from an isolated user namespace (mnt_userns_id != 0),
	 * then we can produce an "isolated" vfsuid and pass it down the VFS
	 * internals.
	 *
	 * See also make_kuid() function.
	 */
	if (mnt_userns_id && (down_uid == (u32) -1)) {
		ns = get_userns_by_id(mnt_userns_id);
		BUG_ON(!ns);
		BUG_ON(!(ns->flags & USERNS_ISOLATED));

		isolated = true;
		res_uid = uid;
		if (isol_debug) printk("make_vfsuid isolated #2 ns id: %d uid: %u\n", mnt_userns_id, res_uid);
	} else {
		res_uid = down_uid;
	}

	return VFSUIDT_INIT(KUIDT_INIT(isolated ? mnt_userns_id : 0, res_uid));
}
EXPORT_SYMBOL_GPL(make_vfsuid);

/**
 * make_vfsgid - map a filesystem kgid according to an idmapping
 * @idmap: the mount's idmapping
 * @fs_userns: the filesystem's idmapping
 * @kgid : kgid to be mapped
 *
 * Take a @kgid and remap it from @fs_userns into @idmap. Use this
 * function when preparing a @kgid to be reported to userspace.
 *
 * If initial_idmapping() determines that this is not an idmapped mount
 * we can simply return @kgid unchanged.
 * If initial_idmapping() tells us that the filesystem is not mounted with an
 * idmapping we know the value of @kgid won't change when calling
 * from_kgid() so we can simply retrieve the value via __kgid_val()
 * directly.
 *
 * Return: @kgid mapped according to @idmap.
 * If @kgid has no mapping in either @idmap or @fs_userns INVALID_GID is
 * returned.
 */
vfsgid_t make_vfsgid(struct mnt_idmap *idmap,
		     struct user_namespace *fs_userns, kgid_t kgid)
{
	bool isolated = false;
	u32 mnt_userns_id = idmap->userns_id;
	gid_t gid;
	u32 down_gid;
	u32 res_gid;

	if (idmap == &nop_mnt_idmap)
		return VFSGIDT_INIT(kgid);
	if (initial_idmapping(fs_userns))
		gid = __kgid_host_gid(kgid);
	else
		gid = from_kgid(fs_userns, kgid);
	if (gid == (gid_t)-1)
		return INVALID_VFSGID;

	down_gid = map_id_down(&idmap->gid_map, gid);

	/* please, look into make_vfsuid() for the explanation */
	if (mnt_userns_id && (down_gid == (u32) -1)) {
		isolated = true;
		res_gid = gid;
	} else {
		res_gid = down_gid;
	}

	return VFSGIDT_INIT(KGIDT_INIT(isolated ? mnt_userns_id : 0, res_gid));
}
EXPORT_SYMBOL_GPL(make_vfsgid);

/**
 * from_vfsuid - map a vfsuid into the filesystem idmapping
 * @idmap: the mount's idmapping
 * @fs_userns: the filesystem's idmapping
 * @vfsuid : vfsuid to be mapped
 *
 * Map @vfsuid into the filesystem idmapping. This function has to be used in
 * order to e.g. write @vfsuid to inode->i_uid.
 *
 * Return: @vfsuid mapped into the filesystem idmapping
 */
kuid_t from_vfsuid(struct mnt_idmap *idmap,
		   struct user_namespace *fs_userns, vfsuid_t vfsuid)
{
	uid_t uid;

	if (isol_debug > 1) {
		printk("from_vfsuid entry idmap nsid %u fs ns: %px current ns %px idmap_nop? %d fs_userns isol? %d vfsuid nsid %u fs userns id %u\n",
		idmap->userns_id, fs_userns, current_user_ns(),
		idmap == &nop_mnt_idmap,
		(fs_userns->flags & USERNS_ISOLATED),
		vfsuid.uns_id,
		fs_userns->id);
	}

	if (idmap == &nop_mnt_idmap)
		return AS_KUIDT(vfsuid);

	if (uid_is_isolated(AS_KUIDT(vfsuid))) {
		/*
		 * Case of host's filesystem bindmount to the container
		 * with container's (isolated) user namespace idmapping applied.
		 *
		 * We have a caller vfsuid (isolated!), we know that our
		 * mount is idmapped one (idmap != &nop_mnt_idmap).
		 * Now we want to ensure that:
		 * - superblock was mounted on the host (init_user_ns)
		 * - mount's idmapping user namespace ID is the same as caller's user namespace ID.
		 *
		 * It these conditions are met, then we are safe to remap vfsuid from
		 * mount's idmapping to the filesystem's idmapping.
		 * As we have idmap->userns_id == vfsuid.uns_id satisfied AND
		 * sb->s_user_ns == &init_user_ns this remapping is trivial
		 * and we just need to return (0, vfsuid.uid_val) as a kuid_t value.
		 *
		 * Of any of these is not true, then we have to return INVALID_UID.
		 *
		 */
		if (initial_idmapping(fs_userns) &&
		    idmap->userns_id &&
		    (idmap->userns_id == vfsuid.uns_id)) {
			printk("from_vfsuid #2 uid: %d\n", vfsuid.uid_val);
			return KUIDT_INIT(0, vfsuid.uid_val);
		}

		/* we can't perform remapping */
		printk("from_vfsuid #3 uid: %d returning INVALID_UID\n", vfsuid.uid_val);
		return INVALID_UID;
	}

	uid = map_id_up(&idmap->uid_map, __vfsuid_uid(vfsuid));
	if (uid == (uid_t)-1)
		return INVALID_UID;
	if (initial_idmapping(fs_userns))
		return KUIDT_INIT(0, uid);
	return make_kuid(fs_userns, uid);
}
EXPORT_SYMBOL_GPL(from_vfsuid);

/**
 * from_vfsgid - map a vfsgid into the filesystem idmapping
 * @idmap: the mount's idmapping
 * @fs_userns: the filesystem's idmapping
 * @vfsgid : vfsgid to be mapped
 *
 * Map @vfsgid into the filesystem idmapping. This function has to be used in
 * order to e.g. write @vfsgid to inode->i_gid.
 *
 * Return: @vfsgid mapped into the filesystem idmapping
 */
kgid_t from_vfsgid(struct mnt_idmap *idmap,
		   struct user_namespace *fs_userns, vfsgid_t vfsgid)
{
	gid_t gid;

	if (idmap == &nop_mnt_idmap)
		return AS_KGIDT(vfsgid);

	if (gid_is_isolated(AS_KGIDT(vfsgid))) {
		/* please, look into from_vfsuid() for the explanation */
		if (initial_idmapping(fs_userns) &&
		    idmap->userns_id &&
		    (idmap->userns_id == vfsgid.uns_id)) {
			return KGIDT_INIT(0, vfsgid.gid_val);
		}

		/* we can't perform remapping */
		return INVALID_GID;
	}

	gid = map_id_up(&idmap->gid_map, __vfsgid_gid(vfsgid));
	if (gid == (gid_t)-1)
		return INVALID_GID;
	if (initial_idmapping(fs_userns))
		return KGIDT_INIT(0, gid);
	return make_kgid(fs_userns, gid);
}
EXPORT_SYMBOL_GPL(from_vfsgid);

#ifdef CONFIG_MULTIUSER
/**
 * vfsgid_in_group_p() - check whether a vfsuid matches the caller's groups
 * @vfsgid: the mnt gid to match
 *
 * This function can be used to determine whether @vfsuid matches any of the
 * caller's groups.
 *
 * Return: 1 if vfsuid matches caller's groups, 0 if not.
 */
int vfsgid_in_group_p(vfsgid_t vfsgid)
{
	return in_group_p(AS_KGIDT(vfsgid));
}
#else
int vfsgid_in_group_p(vfsgid_t vfsgid)
{
	return 1;
}
#endif
EXPORT_SYMBOL_GPL(vfsgid_in_group_p);

static int copy_mnt_idmap(struct uid_gid_map *map_from,
			  struct uid_gid_map *map_to)
{
	struct uid_gid_extent *forward, *reverse;
	u32 nr_extents = READ_ONCE(map_from->nr_extents);
	/* Pairs with smp_wmb() when writing the idmapping. */
	smp_rmb();

	/*
	 * Don't blindly copy @map_to into @map_from if nr_extents is
	 * smaller or equal to UID_GID_MAP_MAX_BASE_EXTENTS. Since we
	 * read @nr_extents someone could have written an idmapping and
	 * then we might end up with inconsistent data. So just don't do
	 * anything at all.
	 */
	if (nr_extents == 0)
		return 0;

	/*
	 * Here we know that nr_extents is greater than zero which means
	 * a map has been written. Since idmappings can't be changed
	 * once they have been written we know that we can safely copy
	 * from @map_to into @map_from.
	 */

	if (nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS) {
		*map_to = *map_from;
		return 0;
	}

	forward = kmemdup_array(map_from->forward, nr_extents,
				sizeof(struct uid_gid_extent),
				GFP_KERNEL_ACCOUNT);
	if (!forward)
		return -ENOMEM;

	reverse = kmemdup_array(map_from->reverse, nr_extents,
				sizeof(struct uid_gid_extent),
				GFP_KERNEL_ACCOUNT);
	if (!reverse) {
		kfree(forward);
		return -ENOMEM;
	}

	/*
	 * The idmapping isn't exposed anywhere so we don't need to care
	 * about ordering between extent pointers and @nr_extents
	 * initialization.
	 */
	map_to->forward = forward;
	map_to->reverse = reverse;
	map_to->nr_extents = nr_extents;
	return 0;
}

static void free_mnt_idmap(struct mnt_idmap *idmap)
{
	if (idmap->uid_map.nr_extents > UID_GID_MAP_MAX_BASE_EXTENTS) {
		kfree(idmap->uid_map.forward);
		kfree(idmap->uid_map.reverse);
	}
	if (idmap->gid_map.nr_extents > UID_GID_MAP_MAX_BASE_EXTENTS) {
		kfree(idmap->gid_map.forward);
		kfree(idmap->gid_map.reverse);
	}
	kfree(idmap);
}

struct mnt_idmap *alloc_mnt_idmap(struct user_namespace *mnt_userns)
{
	struct mnt_idmap *idmap;
	int ret;

	idmap = kzalloc(sizeof(struct mnt_idmap), GFP_KERNEL_ACCOUNT);
	if (!idmap)
		return ERR_PTR(-ENOMEM);

	refcount_set(&idmap->count, 1);
	ret = copy_mnt_idmap(&mnt_userns->uid_map, &idmap->uid_map);
	if (!ret)
		ret = copy_mnt_idmap(&mnt_userns->gid_map, &idmap->gid_map);
	if (ret) {
		free_mnt_idmap(idmap);
		return ERR_PTR(ret);
	}

	if (mnt_userns->flags & USERNS_ISOLATED) {
		idmap->userns_id = mnt_userns->id;
	} else if ((idmap->uid_map.nr_extents == 0) || (idmap->gid_map.nr_extents == 0)) {
		free_mnt_idmap(idmap);
		return ERR_PTR(-EINVAL);
	}

	return idmap;
}

/**
 * mnt_idmap_get - get a reference to an idmapping
 * @idmap: the idmap to bump the reference on
 *
 * If @idmap is not the @nop_mnt_idmap bump the reference count.
 *
 * Return: @idmap with reference count bumped if @not_mnt_idmap isn't passed.
 */
struct mnt_idmap *mnt_idmap_get(struct mnt_idmap *idmap)
{
	if (idmap != &nop_mnt_idmap)
		refcount_inc(&idmap->count);

	return idmap;
}
EXPORT_SYMBOL_GPL(mnt_idmap_get);

/**
 * mnt_idmap_put - put a reference to an idmapping
 * @idmap: the idmap to put the reference on
 *
 * If this is a non-initial idmapping, put the reference count when a mount is
 * released and free it if we're the last user.
 */
void mnt_idmap_put(struct mnt_idmap *idmap)
{
	if (idmap != &nop_mnt_idmap && refcount_dec_and_test(&idmap->count))
		free_mnt_idmap(idmap);
}
EXPORT_SYMBOL_GPL(mnt_idmap_put);
