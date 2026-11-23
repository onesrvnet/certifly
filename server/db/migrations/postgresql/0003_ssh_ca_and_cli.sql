CREATE TYPE "public"."cli_login_status" AS ENUM('pending', 'approved', 'denied');--> statement-breakpoint
CREATE TYPE "public"."group_member_source" AS ENUM('manual', 'oidc');--> statement-breakpoint
CREATE TYPE "public"."ssh_ca_source" AS ENUM('generated', 'imported');--> statement-breakpoint
CREATE TYPE "public"."ssh_certificate_kind" AS ENUM('user', 'host');--> statement-breakpoint
CREATE TYPE "public"."ssh_key_policy" AS ENUM('any', 'sk', 'sk_attested');--> statement-breakpoint
ALTER TYPE "public"."actor_type" ADD VALUE 'cli';--> statement-breakpoint
ALTER TYPE "public"."actor_type" ADD VALUE 'ssh_host';--> statement-breakpoint
ALTER TYPE "public"."alert_event" ADD VALUE 'ssh_host_expiring';--> statement-breakpoint
CREATE TABLE "cli_logins" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"device_code_hash" text NOT NULL,
	"user_code" text NOT NULL,
	"code_challenge" text NOT NULL,
	"machine_hostname" text NOT NULL,
	"machine_os" text NOT NULL,
	"status" "cli_login_status" DEFAULT 'pending' NOT NULL,
	"user_id" uuid,
	"expires_at" timestamp with time zone NOT NULL,
	"last_poll_at" timestamp with time zone,
	"consumed_at" timestamp with time zone,
	"ip" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "cli_logins_device_code_hash_unique" UNIQUE("device_code_hash")
);
--> statement-breakpoint
CREATE TABLE "cli_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"machine_hostname" text NOT NULL,
	"machine_os" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "cli_sessions_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "group_members" (
	"group_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"source" "group_member_source" DEFAULT 'manual' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "group_members_group_id_user_id_pk" PRIMARY KEY("group_id","user_id")
);
--> statement-breakpoint
CREATE TABLE "groups" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"provider_groups" text[] DEFAULT '{}' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ssh_access_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"host_group_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
	"logins" text[] DEFAULT '{}' NOT NULL,
	"own_username" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ssh_ca_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ssh_ca_id" uuid NOT NULL,
	"algorithm" text NOT NULL,
	"public_key_spki" "bytea" NOT NULL,
	"alg" text NOT NULL,
	"kek_id" text NOT NULL,
	"wrapped_dek" "bytea" NOT NULL,
	"dek_iv" "bytea" NOT NULL,
	"dek_tag" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"iv" "bytea" NOT NULL,
	"tag" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ssh_cas" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"key_algorithm" text NOT NULL,
	"source" "ssh_ca_source" NOT NULL,
	"public_key" text NOT NULL,
	"fingerprint" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ssh_cas_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "ssh_certificates" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ssh_ca_id" uuid NOT NULL,
	"kind" "ssh_certificate_kind" NOT NULL,
	"serial" bigint NOT NULL,
	"key_id" text NOT NULL,
	"principals" text[] NOT NULL,
	"public_key" text NOT NULL,
	"fingerprint" text NOT NULL,
	"certificate" text NOT NULL,
	"valid_after" timestamp with time zone NOT NULL,
	"valid_before" timestamp with time zone NOT NULL,
	"host_group_id" uuid,
	"user_id" uuid,
	"requested_by_user_id" uuid,
	"host_id" uuid,
	"attested" boolean DEFAULT false NOT NULL,
	"revoked_at" timestamp with time zone,
	"revocation_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ssh_host_challenges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"host_id" uuid NOT NULL,
	"nonce_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ssh_host_challenges_nonce_hash_unique" UNIQUE("nonce_hash")
);
--> statement-breakpoint
CREATE TABLE "ssh_host_groups" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"ssh_ca_id" uuid NOT NULL,
	"host_patterns" text[] DEFAULT '{}' NOT NULL,
	"user_ttl_default_seconds" integer NOT NULL,
	"user_ttl_max_seconds" integer NOT NULL,
	"user_extensions" text[] DEFAULT '{}' NOT NULL,
	"force_command" text,
	"source_address" text[] DEFAULT '{}' NOT NULL,
	"key_policy" "ssh_key_policy" DEFAULT 'any' NOT NULL,
	"host_ttl_seconds" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ssh_host_groups_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "ssh_hosts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"host_group_id" uuid NOT NULL,
	"hostnames" text[] NOT NULL,
	"public_keys" text[] NOT NULL,
	"last_seen_at" timestamp with time zone,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ssh_join_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"host_group_id" uuid NOT NULL,
	"label" text DEFAULT '' NOT NULL,
	"token_hash" text NOT NULL,
	"last4" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"host_id" uuid,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ssh_join_tokens_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "ssh_krls" (
	"ssh_ca_id" uuid PRIMARY KEY NOT NULL,
	"version" bigint NOT NULL,
	"krl" "bytea" NOT NULL,
	"generated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "username" text;--> statement-breakpoint
ALTER TABLE "cli_logins" ADD CONSTRAINT "cli_logins_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cli_sessions" ADD CONSTRAINT "cli_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "group_members" ADD CONSTRAINT "group_members_group_id_groups_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."groups"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "group_members" ADD CONSTRAINT "group_members_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_access_rules" ADD CONSTRAINT "ssh_access_rules_host_group_id_ssh_host_groups_id_fk" FOREIGN KEY ("host_group_id") REFERENCES "public"."ssh_host_groups"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_access_rules" ADD CONSTRAINT "ssh_access_rules_group_id_groups_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."groups"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_ca_keys" ADD CONSTRAINT "ssh_ca_keys_ssh_ca_id_ssh_cas_id_fk" FOREIGN KEY ("ssh_ca_id") REFERENCES "public"."ssh_cas"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_certificates" ADD CONSTRAINT "ssh_certificates_ssh_ca_id_ssh_cas_id_fk" FOREIGN KEY ("ssh_ca_id") REFERENCES "public"."ssh_cas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_certificates" ADD CONSTRAINT "ssh_certificates_host_group_id_ssh_host_groups_id_fk" FOREIGN KEY ("host_group_id") REFERENCES "public"."ssh_host_groups"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_certificates" ADD CONSTRAINT "ssh_certificates_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_certificates" ADD CONSTRAINT "ssh_certificates_requested_by_user_id_users_id_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_certificates" ADD CONSTRAINT "ssh_certificates_host_id_ssh_hosts_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."ssh_hosts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_host_challenges" ADD CONSTRAINT "ssh_host_challenges_host_id_ssh_hosts_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."ssh_hosts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_host_groups" ADD CONSTRAINT "ssh_host_groups_ssh_ca_id_ssh_cas_id_fk" FOREIGN KEY ("ssh_ca_id") REFERENCES "public"."ssh_cas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_hosts" ADD CONSTRAINT "ssh_hosts_host_group_id_ssh_host_groups_id_fk" FOREIGN KEY ("host_group_id") REFERENCES "public"."ssh_host_groups"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_hosts" ADD CONSTRAINT "ssh_hosts_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_join_tokens" ADD CONSTRAINT "ssh_join_tokens_host_group_id_ssh_host_groups_id_fk" FOREIGN KEY ("host_group_id") REFERENCES "public"."ssh_host_groups"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_join_tokens" ADD CONSTRAINT "ssh_join_tokens_host_id_ssh_hosts_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."ssh_hosts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_join_tokens" ADD CONSTRAINT "ssh_join_tokens_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssh_krls" ADD CONSTRAINT "ssh_krls_ssh_ca_id_ssh_cas_id_fk" FOREIGN KEY ("ssh_ca_id") REFERENCES "public"."ssh_cas"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "cli_logins_expires_idx" ON "cli_logins" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "cli_sessions_user_idx" ON "cli_sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "cli_sessions_expires_idx" ON "cli_sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "group_members_user_idx" ON "group_members" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "groups_name_lower_idx" ON "groups" USING btree (lower("name"));--> statement-breakpoint
CREATE UNIQUE INDEX "ssh_access_rules_pair_idx" ON "ssh_access_rules" USING btree ("host_group_id","group_id");--> statement-breakpoint
CREATE INDEX "ssh_access_rules_group_idx" ON "ssh_access_rules" USING btree ("group_id");--> statement-breakpoint
CREATE UNIQUE INDEX "ssh_ca_keys_ca_idx" ON "ssh_ca_keys" USING btree ("ssh_ca_id");--> statement-breakpoint
CREATE INDEX "ssh_ca_keys_kek_idx" ON "ssh_ca_keys" USING btree ("kek_id");--> statement-breakpoint
CREATE UNIQUE INDEX "ssh_certificates_serial_idx" ON "ssh_certificates" USING btree ("ssh_ca_id","serial");--> statement-breakpoint
CREATE INDEX "ssh_certificates_user_idx" ON "ssh_certificates" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "ssh_certificates_host_idx" ON "ssh_certificates" USING btree ("host_id","created_at");--> statement-breakpoint
CREATE INDEX "ssh_certificates_group_idx" ON "ssh_certificates" USING btree ("host_group_id");--> statement-breakpoint
CREATE INDEX "ssh_certificates_created_idx" ON "ssh_certificates" USING btree ("created_at","id");--> statement-breakpoint
CREATE INDEX "ssh_host_challenges_host_idx" ON "ssh_host_challenges" USING btree ("host_id");--> statement-breakpoint
CREATE INDEX "ssh_host_groups_ca_idx" ON "ssh_host_groups" USING btree ("ssh_ca_id");--> statement-breakpoint
CREATE INDEX "ssh_hosts_group_idx" ON "ssh_hosts" USING btree ("host_group_id");--> statement-breakpoint
CREATE UNIQUE INDEX "ssh_hosts_name_lower_idx" ON "ssh_hosts" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "ssh_join_tokens_group_idx" ON "ssh_join_tokens" USING btree ("host_group_id");--> statement-breakpoint
CREATE UNIQUE INDEX "users_username_lower_idx" ON "users" USING btree (lower("username"));