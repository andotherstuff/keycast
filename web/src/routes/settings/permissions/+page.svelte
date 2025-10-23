<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';

	interface PermissionDetail {
		application_name: string;
		application_id: number;
		policy_name: string;
		policy_id: number;
		allowed_event_kinds: number[];
		event_kind_names: string[];
		created_at: string;
		last_activity: string | null;
		activity_count: number;
		secret: string;
	}

	let permissions: PermissionDetail[] = [];
	let loading = true;
	let error = '';
	let showRevokeModal = false;
	let selectedPermission: PermissionDetail | null = null;

	async function loadPermissions() {
		try {
			loading = true;
			error = '';

			// Get JWT token from localStorage
			const token = localStorage.getItem('token');
			if (!token) {
				error = 'Not authenticated. Please log in.';
				loading = false;
				return;
			}

			const response = await fetch('/api/user/permissions', {
				headers: {
					'Authorization': `Bearer ${token}`
				}
			});

			if (!response.ok) {
				throw new Error(`HTTP ${response.status}: ${await response.text()}`);
			}

			const data = await response.json();
			permissions = data.permissions;
		} catch (err) {
			error = `Failed to load permissions: ${err}`;
			console.error('Load permissions error:', err);
		} finally {
			loading = false;
		}
	}

	async function revokePermission(secret: string) {
		try {
			const token = localStorage.getItem('token');
			const response = await fetch('/api/user/sessions/revoke', {
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${token}`,
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ secret })
			});

			if (!response.ok) {
				throw new Error('Failed to revoke permission');
			}

			// Reload permissions after revoke
			await loadPermissions();
			showRevokeModal = false;
			selectedPermission = null;
		} catch (err) {
			error = `Failed to revoke: ${err}`;
		}
	}

	function formatDate(dateStr: string): string {
		const date = new Date(dateStr);
		return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
	}

	function getRiskBadgeColor(kinds: number[]): string {
		// Check for high-risk kinds
		if (kinds.includes(5)) return 'badge-critical'; // Deletion
		if (kinds.includes(9734)) return 'badge-high'; // Zaps (money)
		if (kinds.includes(23194) || kinds.includes(23195)) return 'badge-critical'; // Wallet
		if (kinds.includes(4) || kinds.includes(44)) return 'badge-sensitive'; // DMs
		return 'badge-safe';
	}

	function getRiskLabel(kinds: number[]): string {
		if (kinds.includes(5)) return 'CRITICAL';
		if (kinds.includes(9734)) return 'HIGH';
		if (kinds.includes(23194) || kinds.includes(23195)) return 'CRITICAL';
		if (kinds.includes(4) || kinds.includes(44)) return 'SENSITIVE';
		return 'MODERATE';
	}

	onMount(() => {
		if (browser) {
			loadPermissions();
		}
	});
</script>

<svelte:head>
	<title>Permissions - Keycast</title>
</svelte:head>

<div class="permissions-page">
	<div class="header">
		<h1>🔐 App Permissions</h1>
		<p class="subtitle">
			Manage which apps can sign events on your behalf
		</p>
	</div>

	{#if loading}
		<div class="loading">
			<div class="spinner"></div>
			<p>Loading permissions...</p>
		</div>
	{:else if error}
		<div class="error-box">
			<h3>Error</h3>
			<p>{error}</p>
			<button on:click={loadPermissions}>Retry</button>
		</div>
	{:else if permissions.length === 0}
		<div class="empty-state">
			<h3>No Active Permissions</h3>
			<p>You haven't authorized any apps yet.</p>
		</div>
	{:else}
		<div class="permissions-list">
			{#each permissions as perm}
				<div class="permission-card">
					<div class="card-header">
						<div>
							<h3>{perm.application_name}</h3>
							<p class="policy-name">Policy: {perm.policy_name}</p>
						</div>
						<div class="card-actions">
							<span class="risk-badge {getRiskBadgeColor(perm.allowed_event_kinds)}">
								{getRiskLabel(perm.allowed_event_kinds)}
							</span>
							<button
								class="btn-revoke"
								on:click={() => {
									selectedPermission = perm;
									showRevokeModal = true;
								}}
							>
								Revoke
							</button>
						</div>
					</div>

					<div class="card-body">
						<div class="info-section">
							<h4>Allowed Actions ({perm.event_kind_names.length})</h4>
							<div class="event-kinds">
								{#each perm.event_kind_names as name}
									<span class="kind-badge">{name}</span>
								{/each}
							</div>
						</div>

						<div class="info-grid">
							<div class="info-item">
								<span class="label">Created:</span>
								<span class="value">{formatDate(perm.created_at)}</span>
							</div>
							<div class="info-item">
								<span class="label">Last Activity:</span>
								<span class="value">
									{perm.last_activity ? formatDate(perm.last_activity) : 'Never'}
								</span>
							</div>
							<div class="info-item">
								<span class="label">Total Signs:</span>
								<span class="value">{perm.activity_count}</span>
							</div>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

{#if showRevokeModal && selectedPermission}
	<div class="modal-overlay" on:click={() => showRevokeModal = false}>
		<div class="modal" on:click|stopPropagation>
			<h3>Revoke Permission?</h3>
			<p>
				Are you sure you want to revoke access for
				<strong>{selectedPermission.application_name}</strong>?
			</p>
			<p class="warning">
				This app will no longer be able to sign events on your behalf.
			</p>
			<div class="modal-actions">
				<button class="btn-cancel" on:click={() => showRevokeModal = false}>
					Cancel
				</button>
				<button
					class="btn-confirm-revoke"
					on:click={() => revokePermission(selectedPermission!.secret)}
				>
					Revoke Access
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.permissions-page {
		max-width: 1200px;
		margin: 0 auto;
		padding: 2rem;
		min-height: 100vh;
		background: #0a0a0a;
		color: #e0e0e0;
	}

	.header {
		margin-bottom: 3rem;
	}

	.header h1 {
		font-size: 2.5rem;
		margin: 0 0 0.5rem 0;
		color: #bb86fc;
	}

	.subtitle {
		color: #999;
		font-size: 1.1rem;
		margin: 0;
	}

	.loading {
		text-align: center;
		padding: 4rem 2rem;
	}

	.spinner {
		width: 50px;
		height: 50px;
		border: 4px solid #333;
		border-top: 4px solid #bb86fc;
		border-radius: 50%;
		animation: spin 1s linear infinite;
		margin: 0 auto 1rem;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.error-box {
		background: #3a1f1f;
		border: 2px solid #f44336;
		border-radius: 8px;
		padding: 2rem;
		text-align: center;
	}

	.error-box h3 {
		color: #f44336;
		margin-top: 0;
	}

	.error-box button {
		margin-top: 1rem;
		padding: 0.5rem 1.5rem;
		background: #bb86fc;
		color: #000;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 1rem;
	}

	.empty-state {
		text-align: center;
		padding: 4rem 2rem;
		color: #999;
	}

	.permissions-list {
		display: grid;
		gap: 1.5rem;
	}

	.permission-card {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		overflow: hidden;
		transition: border-color 0.2s;
	}

	.permission-card:hover {
		border-color: #bb86fc;
	}

	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 1.5rem;
		border-bottom: 1px solid #333;
	}

	.card-header h3 {
		margin: 0 0 0.5rem 0;
		color: #bb86fc;
		font-size: 1.5rem;
	}

	.policy-name {
		margin: 0;
		color: #999;
		font-size: 0.9rem;
	}

	.card-actions {
		display: flex;
		gap: 1rem;
		align-items: center;
	}

	.risk-badge {
		padding: 0.4rem 0.8rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: bold;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.badge-safe {
		background: #1b5e20;
		color: #4caf50;
	}

	.badge-sensitive {
		background: #e65100;
		color: #ff9800;
	}

	.badge-high {
		background: #b71c1c;
		color: #f44336;
	}

	.badge-critical {
		background: #880e4f;
		color: #e91e63;
		animation: pulse 2s ease-in-out infinite;
	}

	@keyframes pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.7; }
	}

	.btn-revoke {
		padding: 0.5rem 1rem;
		background: transparent;
		color: #f44336;
		border: 1px solid #f44336;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.9rem;
		transition: all 0.2s;
	}

	.btn-revoke:hover {
		background: #f44336;
		color: #fff;
	}

	.card-body {
		padding: 1.5rem;
	}

	.info-section {
		margin-bottom: 1.5rem;
	}

	.info-section h4 {
		margin: 0 0 1rem 0;
		color: #03dac6;
		font-size: 1rem;
	}

	.event-kinds {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.kind-badge {
		display: inline-block;
		padding: 0.4rem 0.8rem;
		background: #2a2a2a;
		border: 1px solid #444;
		border-radius: 6px;
		font-size: 0.85rem;
		color: #e0e0e0;
	}

	.info-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
	}

	.info-item {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.label {
		font-size: 0.85rem;
		color: #999;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.value {
		font-size: 1rem;
		color: #e0e0e0;
	}

	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.8);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal {
		background: #1a1a1a;
		border: 1px solid #444;
		border-radius: 12px;
		padding: 2rem;
		max-width: 500px;
		width: 90%;
	}

	.modal h3 {
		margin-top: 0;
		color: #bb86fc;
	}

	.modal .warning {
		color: #f44336;
		font-weight: bold;
	}

	.modal-actions {
		display: flex;
		gap: 1rem;
		margin-top: 2rem;
		justify-content: flex-end;
	}

	.btn-cancel {
		padding: 0.75rem 1.5rem;
		background: #333;
		color: #e0e0e0;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 1rem;
	}

	.btn-confirm-revoke {
		padding: 0.75rem 1.5rem;
		background: #f44336;
		color: #fff;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 1rem;
		font-weight: bold;
	}

	.btn-confirm-revoke:hover {
		background: #d32f2f;
	}
</style>
