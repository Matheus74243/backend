import express, { NextFunction, Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { PrismaClient, Prisma, UserRole, OrderStatus, PaymentStatus } from "@prisma/client";
import { z } from "zod";

/**
 * M110Beauty Admin API
 * Single-file production-style starter for:
 * - Auth
 * - Categories
 * - Brands
 * - Orders
 * - Customers
 *
 * Notes:
 * - This file is intentionally self-contained for quick setup and review.
 * - Stripe, Cloudinary, Redis, email, and PDF/XLSX integrations are stubbed with safe placeholders.
 * - Assumes the Prisma schema includes models discussed in your uploaded specs.
 */

const app = express();
const prisma = new PrismaClient();

app.use(helmet());
app.use(
  cors({
    origin: [
      "https://m110beauty.ge",
      "https://www.m110beauty.ge",
      "https://admin.m110beauty.ge",
    ],
    credentials: true,
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many admin login attempts. Try again later." },
});

app.use("/api/v1", apiLimiter);

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "dev_access_secret";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "dev_refresh_secret";
const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_COOKIE = "m110_rt";
const REFRESH_TOKEN_DAYS = 7;
const BCRYPT_ROUNDS = 12;

type AuthUser = {
  id: number;
  email: string;
  role: UserRole;
};

type ApiRequest<TBody = unknown, TQuery = unknown> = Request & {
  user?: AuthUser;
  validatedBody?: TBody;
  validatedQuery?: TQuery;
};

class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor(status: number, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function slugify(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

function romanizeGeorgian(text: string): string {
  const map: Record<string, string> = {
    ა: "a", ბ: "b", გ: "g", დ: "d", ე: "e", ვ: "v", ზ: "z", თ: "t", ი: "i", კ: "k",
    ლ: "l", მ: "m", ნ: "n", ო: "o", პ: "p", ჟ: "zh", რ: "r", ს: "s", ტ: "t", უ: "u",
    ფ: "f", ქ: "q", ღ: "gh", ყ: "y", შ: "sh", ჩ: "ch", ც: "ts", ძ: "dz", წ: "ts", ჭ: "ch",
    ხ: "kh", ჯ: "j", ჰ: "h",
  };

  return slugify(
    [...text]
      .map((char) => map[char] ?? char)
      .join("")
  );
}

function buildAccessToken(user: AuthUser): string {
  return jwt.sign(user, JWT_ACCESS_SECRET, { expiresIn: ACCESS_TOKEN_TTL });
}

function buildRefreshToken(user: AuthUser): string {
  return jwt.sign(user, JWT_REFRESH_SECRET, { expiresIn: `${REFRESH_TOKEN_DAYS}d` });
}

async function hashToken(token: string): Promise<string> {
  return bcrypt.hash(token, 10);
}

async function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
  return bcrypt.compare(password, passwordHash);
}

function setRefreshCookie(res: Response, token: string): void {
  res.cookie(REFRESH_TOKEN_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000,
    path: "/api/v1/auth",
  });
}

function clearRefreshCookie(res: Response): void {
  res.clearCookie(REFRESH_TOKEN_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/api/v1/auth",
  });
}

async function logSecurityEvent(data: {
  userId?: number | null;
  email?: string | null;
  event: string;
  ip?: string | null;
  metadata?: Record<string, unknown>;
}) {
  const model = (prisma as unknown as { securityLog?: { create: Function } }).securityLog;
  if (!model) return;
  await model.create({
    data: {
      user_id: data.userId ?? null,
      email: data.email ?? null,
      event: data.event,
      ip: data.ip ?? null,
      metadata: data.metadata ? JSON.stringify(data.metadata) : null,
    },
  });
}

async function logAudit(data: {
  adminId: number;
  action: string;
  entity: string;
  entityId?: number | null;
  changes?: unknown;
  ip?: string | null;
}) {
  const model = (prisma as unknown as { auditLog?: { create: Function } }).auditLog;
  if (!model) return;
  await model.create({
    data: {
      admin_id: data.adminId,
      action: data.action,
      entity: data.entity,
      entity_id: data.entityId ?? null,
      changes: data.changes ? JSON.stringify(data.changes) : null,
      ip: data.ip ?? null,
    },
  });
}

async function logAdminAudit(data: {
  adminId: number;
  action: string;
  ip?: string | null;
  metadata?: unknown;
}) {
  const model = (prisma as unknown as { adminAuditLog?: { create: Function } }).adminAuditLog;
  if (!model) return;
  await model.create({
    data: {
      admin_id: data.adminId,
      action: data.action,
      ip: data.ip ?? null,
      metadata: data.metadata ? JSON.stringify(data.metadata) : null,
    },
  });
}

function authenticateToken(req: ApiRequest, _res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return next(new ApiError(401, "Unauthorized"));

  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET) as AuthUser;
    req.user = payload;
    return next();
  } catch {
    return next(new ApiError(401, "Invalid or expired token"));
  }
}

function requireRole(roles: UserRole[]) {
  return (req: ApiRequest, _res: Response, next: NextFunction) => {
    if (!req.user) return next(new ApiError(401, "Unauthorized"));
    if (!roles.includes(req.user.role)) return next(new ApiError(403, "Forbidden"));
    next();
  };
}

function validateRequest<TBody = unknown, TQuery = unknown>(schemas: {
  body?: z.ZodType<TBody>;
  query?: z.ZodType<TQuery>;
}) {
  return (req: ApiRequest<TBody, TQuery>, _res: Response, next: NextFunction) => {
    try {
      if (schemas.body) req.validatedBody = schemas.body.parse(req.body);
      if (schemas.query) req.validatedQuery = schemas.query.parse(req.query);
      next();
    } catch (error) {
      next(new ApiError(400, "Validation error", error));
    }
  };
}

function jsonOk(res: Response, data: unknown, meta?: unknown) {
  return res.status(200).json(meta ? { data, meta } : { data });
}

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  first_name: z.string().min(1).optional(),
  last_name: z.string().min(1).optional(),
  phone: z.string().min(5).optional(),
  language_pref: z.enum(["ka", "en"]).default("ka"),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resetPasswordSchema = z.object({
  email: z.string().email(),
  otp: z.string().length(6),
  new_password: z.string().min(8),
});

const emailVerifySchema = z.object({
  token: z.string().min(10),
});

const categoryBodySchema = z.object({
  name_ka: z.string().min(2).optional(),
  name_en: z.string().min(2).optional(),
  description_ka: z.string().optional().nullable(),
  description_en: z.string().optional().nullable(),
  parent_id: z.number().int().positive().nullable().optional(),
  sort_order: z.number().int().min(0).optional(),
  image_url: z.string().url().optional().nullable(),
  is_active: z.boolean().optional(),
  meta_title_ka: z.string().optional().nullable(),
  meta_title_en: z.string().optional().nullable(),
  meta_desc_ka: z.string().optional().nullable(),
  meta_desc_en: z.string().optional().nullable(),
});

const reorderSchema = z.object({
  ordered_ids: z.array(z.number().int().positive()).min(1),
});

const brandBodySchema = z.object({
  name: z.string().min(2).optional(),
  slug: z.string().min(2).optional(),
  logo_url: z.string().url().optional().nullable(),
  is_active: z.boolean().optional(),
});

const ordersListQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
  search: z.string().optional(),
  status: z.nativeEnum(OrderStatus).optional(),
  payment_status: z.nativeEnum(PaymentStatus).optional(),
  date_from: z.string().date().optional(),
  date_to: z.string().date().optional(),
  sort_by: z.enum(["created_at", "total", "status"]).default("created_at"),
  sort_order: z.enum(["asc", "desc"]).default("desc"),
});

const orderStatusSchema = z.object({
  status: z.nativeEnum(OrderStatus),
  tracking_number: z.string().optional().nullable(),
  tracking_url: z.string().url().optional().nullable(),
  notify_customer: z.boolean().default(false),
  note: z.string().max(1000).optional().nullable(),
});

const refundSchema = z.object({
  type: z.enum(["full", "partial"]),
  amount: z.number().positive(),
  reason: z.string().min(3),
  refund_items: z.array(
    z.object({
      order_item_id: z.number().int().positive(),
      quantity: z.number().int().positive(),
    })
  ).optional().default([]),
  restock_items: z.boolean().default(false),
});

const orderNoteSchema = z.object({
  note: z.string().min(2).max(2000),
});

const customersListQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
  search: z.string().optional(),
  status: z.enum(["active", "blocked"]).optional(),
  sort_by: z.enum(["created_at", "total_spent", "orders"]).default("created_at"),
  sort_order: z.enum(["asc", "desc"]).default("desc"),
});

const customerUpdateSchema = z.object({
  is_active: z.boolean().optional(),
  loyalty_points: z.number().int().optional(),
  role: z.nativeEnum(UserRole).optional(),
  email: z.string().email().optional(),
});

const loyaltyPointsSchema = z.object({
  adjustment: z.number().int(),
  reason: z.string().min(2),
});

const blockCustomerSchema = z.object({
  reason: z.string().min(3),
});

function requireId(paramName = "id") {
  return (req: Request, _res: Response, next: NextFunction) => {
    const id = Number(req.params[paramName]);
    if (!Number.isInteger(id) || id <= 0) return next(new ApiError(400, `Invalid ${paramName}`));
    next();
  };
}

function ensureStatusTransition(current: OrderStatus, next: OrderStatus) {
  const allowed: Record<OrderStatus, OrderStatus[]> = {
    PENDING: ["PROCESSING", "CANCELLED"],
    PROCESSING: ["SHIPPED", "CANCELLED"],
    SHIPPED: ["DELIVERED", "CANCELLED"],
    DELIVERED: ["REFUNDED"],
    CANCELLED: [],
    REFUNDED: [],
    ON_HOLD: ["PROCESSING", "CANCELLED"],
  };

  if (!allowed[current].includes(next)) {
    throw new ApiError(400, `Invalid status transition: ${current} -> ${next}`);
  }
}

async function sendBilingualEmail(input: {
  to: string;
  subject_ka: string;
  subject_en: string;
  body_ka: string;
  body_en: string;
  language_pref?: string | null;
}) {
  console.log("EMAIL_STUB", input);
}

async function createOtpCode(): Promise<string> {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function processStripeRefund(input: { paymentIntentId?: string | null; amount: number; reason: string }) {
  console.log("STRIPE_REFUND_STUB", input);
  return { provider_refund_id: `refund_${Date.now()}` };
}

async function uploadToCloudinaryStub(input: { folder: string }) {
  return { secure_url: `https://res.cloudinary.com/demo/${input.folder}/${Date.now()}.webp` };
}

async function generateInvoicePdfStub(orderId: number): Promise<Buffer> {
  return Buffer.from(`Invoice PDF for order ${orderId}`);
}

async function generateOrdersXlsxStub(query: unknown): Promise<Buffer> {
  return Buffer.from(JSON.stringify(query, null, 2));
}

async function generateCustomersXlsxStub(): Promise<Buffer> {
  return Buffer.from("customers export");
}

function toPagination(page: number, limit: number, total: number) {
  return { page, limit, total, total_pages: Math.ceil(total / limit) || 1 };
}

async function buildCategoryTree() {
  const categories = await prisma.category.findMany({
    orderBy: [{ sort_order: "asc" }, { id: "asc" }],
    include: {
      _count: { select: { products: true, children: true } },
    },
  });

  type TreeNode = typeof categories[number] & { product_count: number; children: TreeNode[] };
  const byId = new Map<number, TreeNode>();
  const roots: TreeNode[] = [];

  for (const category of categories) {
    byId.set(category.id, {
      ...category,
      product_count: category._count.products,
      children: [],
    });
  }

  for (const category of categories) {
    const node = byId.get(category.id)!;
    if (category.parent_id && byId.has(category.parent_id)) {
      byId.get(category.parent_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots;
}

const authRouter = express.Router();
const adminCategoriesRouter = express.Router();
const adminBrandsRouter = express.Router();
const adminOrdersRouter = express.Router();
const adminCustomersRouter = express.Router();

authRouter.post(
  "/register",
  validateRequest({ body: registerSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof registerSchema>>, res) => {
    const body = req.validatedBody!;
    const existing = await prisma.user.findUnique({ where: { email: body.email } });
    if (existing) throw new ApiError(409, "Email already exists");

    const password_hash = await bcrypt.hash(body.password, BCRYPT_ROUNDS);
    const user = await prisma.user.create({
      data: {
        email: body.email,
        password_hash,
        first_name: body.first_name,
        last_name: body.last_name,
        phone: body.phone,
        language_pref: body.language_pref,
        role: UserRole.CUSTOMER,
      },
    });

    await logSecurityEvent({ userId: user.id, email: user.email, event: "REGISTER", ip: req.ip });

    res.status(201).json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  })
);

authRouter.post(
  "/login",
  validateRequest({ body: loginSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof loginSchema>>, res) => {
    const body = req.validatedBody!;
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    if (!user || !user.password_hash) {
      await logSecurityEvent({ email: body.email, event: "LOGIN_FAILED", ip: req.ip });
      throw new ApiError(401, "Invalid credentials");
    }
    if (!user.is_active) throw new ApiError(403, "User is blocked");

    const valid = await verifyPassword(body.password, user.password_hash);
    if (!valid) {
      await logSecurityEvent({ userId: user.id, email: user.email, event: "LOGIN_FAILED", ip: req.ip });
      throw new ApiError(401, "Invalid credentials");
    }

    const authUser: AuthUser = { id: user.id, email: user.email, role: user.role };
    const accessToken = buildAccessToken(authUser);
    const refreshToken = buildRefreshToken(authUser);
    const refreshTokenHash = await hashToken(refreshToken);

    const refreshModel = (prisma as unknown as { refreshToken?: { create: Function } }).refreshToken;
    if (refreshModel) {
      await refreshModel.create({
        data: {
          user_id: user.id,
          token_hash: refreshTokenHash,
          expires_at: new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000),
        },
      });
    }

    await prisma.user.update({ where: { id: user.id }, data: { last_login: new Date() } });
    await logSecurityEvent({ userId: user.id, email: user.email, event: "LOGIN_SUCCESS", ip: req.ip });

    setRefreshCookie(res, refreshToken);

    jsonOk(res, {
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
        language_pref: user.language_pref,
      },
    });
  })
);

authRouter.post(
  "/admin/login",
  adminLoginLimiter,
  validateRequest({ body: loginSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof loginSchema>>, res) => {
    const body = req.validatedBody!;
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    if (!user || !user.password_hash) throw new ApiError(401, "Invalid credentials");
    if (!user.is_active) throw new ApiError(403, "User is blocked");
    if (user.role === UserRole.CUSTOMER) throw new ApiError(403, "Admin access required");

    const valid = await verifyPassword(body.password, user.password_hash);
    if (!valid) {
      await logSecurityEvent({ userId: user.id, email: user.email, event: "ADMIN_LOGIN_FAILED", ip: req.ip });
      throw new ApiError(401, "Invalid credentials");
    }

    const authUser: AuthUser = { id: user.id, email: user.email, role: user.role };
    const accessToken = buildAccessToken(authUser);
    const refreshToken = buildRefreshToken(authUser);
    const refreshTokenHash = await hashToken(refreshToken);

    const refreshModel = (prisma as unknown as { refreshToken?: { create: Function } }).refreshToken;
    if (refreshModel) {
      await refreshModel.create({
        data: {
          user_id: user.id,
          token_hash: refreshTokenHash,
          expires_at: new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000),
        },
      });
    }

    setRefreshCookie(res, refreshToken);
    await logAdminAudit({ adminId: user.id, action: "ADMIN_LOGIN", ip: req.ip });
    await logSecurityEvent({ userId: user.id, email: user.email, event: "ADMIN_LOGIN_SUCCESS", ip: req.ip });

    jsonOk(res, {
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  })
);

authRouter.post(
  "/refresh",
  asyncHandler(async (req: Request, res) => {
    const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE];
    if (!refreshToken) throw new ApiError(401, "Missing refresh token");

    let payload: AuthUser;
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as AuthUser;
    } catch {
      throw new ApiError(401, "Invalid refresh token");
    }

    const refreshModel = (prisma as unknown as { refreshToken?: { findMany: Function; update: Function; create: Function } }).refreshToken;
    if (!refreshModel) throw new ApiError(500, "Refresh token model not configured");

    const activeTokens = await refreshModel.findMany({ where: { user_id: payload.id, is_revoked: false } });
    let matchedToken: { id: number } | null = null;

    for (const tokenRow of activeTokens) {
      const match = await bcrypt.compare(refreshToken, tokenRow.token_hash);
      if (match) {
        matchedToken = tokenRow;
        break;
      }
    }

    if (!matchedToken) throw new ApiError(401, "Refresh token not recognized");

    await refreshModel.update({ where: { id: matchedToken.id }, data: { is_revoked: true } });

    const newAuthUser: AuthUser = { id: payload.id, email: payload.email, role: payload.role };
    const newAccessToken = buildAccessToken(newAuthUser);
    const newRefreshToken = buildRefreshToken(newAuthUser);
    const newRefreshHash = await hashToken(newRefreshToken);

    await refreshModel.create({
      data: {
        user_id: payload.id,
        token_hash: newRefreshHash,
        expires_at: new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000),
      },
    });

    setRefreshCookie(res, newRefreshToken);
    jsonOk(res, { accessToken: newAccessToken });
  })
);

authRouter.post(
  "/logout",
  asyncHandler(async (req: Request, res) => {
    const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE];
    const refreshModel = (prisma as unknown as { refreshToken?: { findMany: Function; update: Function } }).refreshToken;

    if (refreshToken && refreshModel) {
      try {
        const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as AuthUser;
        const rows = await refreshModel.findMany({ where: { user_id: payload.id, is_revoked: false } });
        for (const row of rows) {
          const match = await bcrypt.compare(refreshToken, row.token_hash);
          if (match) {
            await refreshModel.update({ where: { id: row.id }, data: { is_revoked: true } });
            break;
          }
        }
      } catch {
        // Ignore invalid token on logout.
      }
    }

    clearRefreshCookie(res);
    jsonOk(res, { success: true });
  })
);

authRouter.post(
  "/forgot-password",
  validateRequest({ body: forgotPasswordSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof forgotPasswordSchema>>, res) => {
    const { email } = req.validatedBody!;
    const user = await prisma.user.findUnique({ where: { email } });
    if (user) {
      const otp = await createOtpCode();
      const otpHash = await bcrypt.hash(otp, 10);
      const otpModel = (prisma as unknown as { passwordResetOtp?: { create: Function } }).passwordResetOtp;
      if (otpModel) {
        await otpModel.create({
          data: {
            user_id: user.id,
            otp_hash: otpHash,
            expires_at: new Date(Date.now() + 15 * 60 * 1000),
            is_used: false,
          },
        });
      }
      await sendBilingualEmail({
        to: user.email,
        language_pref: user.language_pref,
        subject_ka: "პაროლის აღდგენა",
        subject_en: "Password reset",
        body_ka: `თქვენი კოდი: ${otp}`,
        body_en: `Your reset code: ${otp}`,
      });
    }

    jsonOk(res, { success: true });
  })
);

authRouter.post(
  "/reset-password",
  validateRequest({ body: resetPasswordSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof resetPasswordSchema>>, res) => {
    const body = req.validatedBody!;
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    if (!user) throw new ApiError(400, "Invalid request");

    const otpModel = (prisma as unknown as {
      passwordResetOtp?: { findFirst: Function; update: Function };
      refreshToken?: { updateMany: Function };
    });

    if (!otpModel.passwordResetOtp) throw new ApiError(500, "OTP model not configured");

    const otpRow = await otpModel.passwordResetOtp.findFirst({
      where: {
        user_id: user.id,
        is_used: false,
        expires_at: { gt: new Date() },
      },
      orderBy: { id: "desc" },
    });

    if (!otpRow) throw new ApiError(400, "OTP expired or invalid");
    const validOtp = await bcrypt.compare(body.otp, otpRow.otp_hash);
    if (!validOtp) throw new ApiError(400, "OTP expired or invalid");

    const password_hash = await bcrypt.hash(body.new_password, BCRYPT_ROUNDS);
    await prisma.user.update({ where: { id: user.id }, data: { password_hash } });
    await otpModel.passwordResetOtp.update({ where: { id: otpRow.id }, data: { is_used: true } });
    if (otpModel.refreshToken) {
      await otpModel.refreshToken.updateMany({ where: { user_id: user.id, is_revoked: false }, data: { is_revoked: true } });
    }

    await logSecurityEvent({ userId: user.id, email: user.email, event: "PASSWORD_RESET_SUCCESS", ip: req.ip });
    jsonOk(res, { success: true });
  })
);

authRouter.post(
  "/verify-email",
  validateRequest({ body: emailVerifySchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof emailVerifySchema>>, res) => {
    const token = req.validatedBody!.token;
    const emailTokenModel = (prisma as unknown as { emailVerificationToken?: { findFirst: Function; update: Function } }).emailVerificationToken;
    if (!emailTokenModel) throw new ApiError(500, "Email verification model not configured");

    const tokenRow = await emailTokenModel.findFirst({ where: { token, is_used: false, expires_at: { gt: new Date() } } });
    if (!tokenRow) throw new ApiError(400, "Invalid verification token");

    await prisma.user.update({ where: { id: tokenRow.user_id }, data: { is_verified: true } });
    await emailTokenModel.update({ where: { id: tokenRow.id }, data: { is_used: true } });

    jsonOk(res, { success: true });
  })
);

adminCategoriesRouter.use(authenticateToken, requireRole([UserRole.ADMIN, UserRole.SUPER_ADMIN]));

adminCategoriesRouter.get(
  "/",
  asyncHandler(async (_req, res) => {
    const tree = await buildCategoryTree();
    jsonOk(res, tree);
  })
);

adminCategoriesRouter.post(
  "/",
  validateRequest({ body: categoryBodySchema.extend({ name_ka: z.string().min(2), name_en: z.string().min(2) }) }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof categoryBodySchema> & { name_ka: string; name_en: string }>, res) => {
    const body = req.validatedBody!;

    if (body.parent_id) {
      const parent = await prisma.category.findUnique({ where: { id: body.parent_id } });
      if (!parent) throw new ApiError(400, "parent_id does not exist");
    }

    const image = body.image_url ?? (await uploadToCloudinaryStub({ folder: "m110beauty/categories" })).secure_url;
    const slug_ka = romanizeGeorgian(body.name_ka);
    const slug_en = slugify(body.name_en);

    const created = await prisma.category.create({
      data: {
        ...body,
        image_url: image,
        slug_ka,
        slug_en,
      },
    });

    await logAudit({
      adminId: req.user!.id,
      action: "CREATE_CATEGORY",
      entity: "Category",
      entityId: created.id,
      changes: body,
      ip: req.ip,
    });

    res.status(201).json({ data: created });
  })
);

adminCategoriesRouter.put(
  "/reorder",
  validateRequest({ body: reorderSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof reorderSchema>>, res) => {
    const { ordered_ids } = req.validatedBody!;

    await prisma.$transaction(
      ordered_ids.map((id, index) =>
        prisma.category.update({ where: { id }, data: { sort_order: index + 1 } })
      )
    );

    await logAudit({
      adminId: req.user!.id,
      action: "REORDER_CATEGORIES",
      entity: "Category",
      changes: ordered_ids,
      ip: req.ip,
    });

    jsonOk(res, { success: true });
  })
);

adminCategoriesRouter.put(
  "/:id",
  requireId(),
  validateRequest({ body: categoryBodySchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof categoryBodySchema>>, res) => {
    const id = Number(req.params.id);
    const body = req.validatedBody!;

    const existing = await prisma.category.findUnique({ where: { id } });
    if (!existing) throw new ApiError(404, "Category not found");
    if (body.parent_id && body.parent_id === id) throw new ApiError(400, "Category cannot be its own parent");

    if (body.parent_id) {
      const parent = await prisma.category.findUnique({ where: { id: body.parent_id } });
      if (!parent) throw new ApiError(400, "parent_id does not exist");
    }

    const updated = await prisma.category.update({
      where: { id },
      data: {
        ...body,
        ...(body.name_ka ? { slug_ka: romanizeGeorgian(body.name_ka) } : {}),
        ...(body.name_en ? { slug_en: slugify(body.name_en) } : {}),
      },
    });

    await logAudit({
      adminId: req.user!.id,
      action: "UPDATE_CATEGORY",
      entity: "Category",
      entityId: id,
      changes: body,
      ip: req.ip,
    });

    jsonOk(res, updated);
  })
);

adminCategoriesRouter.delete(
  "/:id",
  requireId(),
  asyncHandler(async (req: ApiRequest, res) => {
    const id = Number(req.params.id);
    const category = await prisma.category.findUnique({
      where: { id },
      include: {
        children: true,
        products: {
          select: { id: true, sku: true, name_ka: true, name_en: true },
          take: 20,
        },
      },
    });

    if (!category) throw new ApiError(404, "Category not found");
    if (category.products.length > 0) {
      throw new ApiError(409, "Category has products", { products: category.products });
    }
    if (category.children.length > 0) {
      throw new ApiError(409, "Category has child categories", {
        child_ids: category.children.map((child) => child.id),
      });
    }

    await prisma.category.delete({ where: { id } });
    await logAudit({ adminId: req.user!.id, action: "DELETE_CATEGORY", entity: "Category", entityId: id, ip: req.ip });

    jsonOk(res, { success: true });
  })
);

adminBrandsRouter.use(authenticateToken, requireRole([UserRole.ADMIN, UserRole.SUPER_ADMIN]));

adminBrandsRouter.get(
  "/",
  asyncHandler(async (_req, res) => {
    const brands = await prisma.brand.findMany({
      orderBy: [{ name: "asc" }],
      include: { _count: { select: { products: true } } },
    });

    jsonOk(
      res,
      brands.map((brand) => ({
        ...brand,
        product_count: brand._count.products,
      }))
    );
  })
);

adminBrandsRouter.post(
  "/",
  validateRequest({ body: brandBodySchema.extend({ name: z.string().min(2) }) }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof brandBodySchema> & { name: string }>, res) => {
    const body = req.validatedBody!;
    const created = await prisma.brand.create({
      data: {
        name: body.name,
        slug: body.slug || slugify(body.name),
        logo_url: body.logo_url || (await uploadToCloudinaryStub({ folder: "m110beauty/brands" })).secure_url,
        is_active: body.is_active ?? true,
      },
    });

    await logAudit({ adminId: req.user!.id, action: "CREATE_BRAND", entity: "Brand", entityId: created.id, changes: body, ip: req.ip });
    res.status(201).json({ data: created });
  })
);

adminBrandsRouter.put(
  "/:id",
  requireId(),
  validateRequest({ body: brandBodySchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof brandBodySchema>>, res) => {
    const id = Number(req.params.id);
    const body = req.validatedBody!;
    const existing = await prisma.brand.findUnique({ where: { id } });
    if (!existing) throw new ApiError(404, "Brand not found");

    const updated = await prisma.brand.update({ where: { id }, data: body });
    await logAudit({ adminId: req.user!.id, action: "UPDATE_BRAND", entity: "Brand", entityId: id, changes: body, ip: req.ip });
    jsonOk(res, updated);
  })
);

adminBrandsRouter.delete(
  "/:id",
  requireId(),
  asyncHandler(async (req: ApiRequest, res) => {
    const id = Number(req.params.id);
    const brand = await prisma.brand.findUnique({
      where: { id },
      include: {
        products: {
          select: { id: true, sku: true, name_ka: true, name_en: true },
          take: 20,
        },
      },
    });
    if (!brand) throw new ApiError(404, "Brand not found");
    if (brand.products.length > 0) {
      throw new ApiError(409, "Brand has products", { products: brand.products });
    }

    await prisma.brand.delete({ where: { id } });
    await logAudit({ adminId: req.user!.id, action: "DELETE_BRAND", entity: "Brand", entityId: id, ip: req.ip });
    jsonOk(res, { success: true });
  })
);

adminOrdersRouter.use(authenticateToken, requireRole([UserRole.ADMIN, UserRole.SUPER_ADMIN]));

adminOrdersRouter.get(
  "/",
  validateRequest({ query: ordersListQuerySchema }),
  asyncHandler(async (req: ApiRequest<unknown, z.infer<typeof ordersListQuerySchema>>, res) => {
    const q = req.validatedQuery!;
    const skip = (q.page - 1) * q.limit;

    const where: Prisma.OrderWhereInput = {
      ...(q.status ? { status: q.status } : {}),
      ...(q.payment_status ? { payment_status: q.payment_status } : {}),
      ...(q.date_from || q.date_to
        ? {
            created_at: {
              ...(q.date_from ? { gte: new Date(q.date_from) } : {}),
              ...(q.date_to ? { lte: new Date(`${q.date_to}T23:59:59.999Z`) } : {}),
            },
          }
        : {}),
      ...(q.search
        ? {
            OR: [
              { order_number: { contains: q.search, mode: "insensitive" } },
              { guest_email: { contains: q.search, mode: "insensitive" } },
              { user: { email: { contains: q.search, mode: "insensitive" } } },
              { user: { first_name: { contains: q.search, mode: "insensitive" } } },
              { user: { last_name: { contains: q.search, mode: "insensitive" } } },
            ],
          }
        : {}),
    };

    const [rows, total] = await prisma.$transaction([
      prisma.order.findMany({
        where,
        skip,
        take: q.limit,
        orderBy: { [q.sort_by]: q.sort_order },
        include: {
          user: { select: { first_name: true, last_name: true, email: true } },
          _count: { select: { items: true } },
        },
      }),
      prisma.order.count({ where }),
    ]);

    jsonOk(
      res,
      rows.map((row) => ({
        id: row.id,
        order_number: row.order_number,
        customer_name: row.user ? `${row.user.first_name ?? ""} ${row.user.last_name ?? ""}`.trim() : null,
        customer_email: row.user?.email ?? row.guest_email,
        status: row.status,
        payment_status: row.payment_status,
        total: row.total,
        items_count: row._count.items,
        created_at: row.created_at,
      })),
      { pagination: toPagination(q.page, q.limit, total) }
    );
  })
);

adminOrdersRouter.get(
  "/stats",
  asyncHandler(async (_req, res) => {
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekStart = new Date(todayStart);
    weekStart.setDate(todayStart.getDate() - todayStart.getDay() + 1);
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

    const [todayOrders, weekOrders, monthOrders, pendingCount, processingCount, allPaid] = await prisma.$transaction([
      prisma.order.findMany({ where: { created_at: { gte: todayStart } }, select: { total: true } }),
      prisma.order.findMany({ where: { created_at: { gte: weekStart } }, select: { total: true } }),
      prisma.order.findMany({ where: { created_at: { gte: monthStart } }, select: { total: true } }),
      prisma.order.count({ where: { status: OrderStatus.PENDING } }),
      prisma.order.count({ where: { status: OrderStatus.PROCESSING } }),
      prisma.order.findMany({ where: { payment_status: PaymentStatus.PAID }, select: { total: true } }),
    ]);

    const sum = (rows: Array<{ total: Prisma.Decimal }>) => rows.reduce((acc, row) => acc + Number(row.total), 0);
    const avgOrderValue = allPaid.length ? sum(allPaid) / allPaid.length : 0;

    jsonOk(res, {
      today: { count: todayOrders.length, revenue: sum(todayOrders) },
      this_week: { count: weekOrders.length, revenue: sum(weekOrders) },
      this_month: { count: monthOrders.length, revenue: sum(monthOrders) },
      pending_count: pendingCount,
      processing_count: processingCount,
      avg_order_value: Number(avgOrderValue.toFixed(2)),
    });
  })
);

adminOrdersRouter.get(
  "/export",
  validateRequest({ query: ordersListQuerySchema }),
  asyncHandler(async (req: ApiRequest<unknown, z.infer<typeof ordersListQuerySchema>>, res) => {
    const q = req.validatedQuery!;
    if (!q.date_from || !q.date_to) throw new ApiError(400, "date_from and date_to are required for export");
    const fileBuffer = await generateOrdersXlsxStub(q);
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", 'attachment; filename="orders-export.xlsx"');
    res.send(fileBuffer);
  })
);

adminOrdersRouter.get(
  "/:id",
  requireId(),
  asyncHandler(async (req: ApiRequest, res) => {
    const id = Number(req.params.id);
    const order = await prisma.order.findUnique({
      where: { id },
      include: {
        user: true,
        items: true,
        shipping_address: true,
      },
    });
    if (!order) throw new ApiError(404, "Order not found");

    const statusHistoryModel = (prisma as unknown as { orderStatusHistory?: { findMany: Function } }).orderStatusHistory;
    const noteModel = (prisma as unknown as { orderNote?: { findMany: Function } }).orderNote;
    const refundModel = (prisma as unknown as { refundHistory?: { findMany: Function } }).refundHistory;

    const [status_history, admin_notes, refund_history] = await Promise.all([
      statusHistoryModel ? statusHistoryModel.findMany({ where: { order_id: id }, orderBy: { created_at: "asc" } }) : [],
      noteModel ? noteModel.findMany({ where: { order_id: id }, orderBy: { created_at: "desc" } }) : [],
      refundModel ? refundModel.findMany({ where: { order_id: id }, orderBy: { created_at: "desc" } }) : [],
    ]);

    jsonOk(res, {
      ...order,
      status_history,
      admin_notes,
      refund_history,
    });
  })
);

adminOrdersRouter.put(
  "/:id/status",
  requireId(),
  validateRequest({ body: orderStatusSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof orderStatusSchema>>, res) => {
    const id = Number(req.params.id);
    const body = req.validatedBody!;

    const order = await prisma.order.findUnique({ where: { id }, include: { user: true } });
    if (!order) throw new ApiError(404, "Order not found");

    ensureStatusTransition(order.status, body.status);

    const updated = await prisma.order.update({
      where: { id },
      data: {
        status: body.status,
        tracking_number: body.tracking_number ?? order.tracking_number,
        ...(body.status === OrderStatus.SHIPPED ? { shipped_at: new Date() } : {}),
        ...(body.status === OrderStatus.DELIVERED ? { delivered_at: new Date() } : {}),
      },
    });

    const historyModel = (prisma as unknown as { orderStatusHistory?: { create: Function } }).orderStatusHistory;
    if (historyModel) {
      await historyModel.create({
        data: {
          order_id: id,
          previous_status: order.status,
          new_status: body.status,
          tracking_number: body.tracking_number ?? null,
          tracking_url: body.tracking_url ?? null,
          note: body.note ?? null,
          changed_by_admin_id: req.user!.id,
        },
      });
    }

    if (body.notify_customer && (order.user?.email || order.guest_email)) {
      await sendBilingualEmail({
        to: order.user?.email || order.guest_email!,
        language_pref: order.user?.language_pref,
        subject_ka: `შეკვეთის სტატუსი განახლდა: ${order.order_number}`,
        subject_en: `Order status updated: ${order.order_number}`,
        body_ka: `ახალი სტატუსი: ${body.status}`,
        body_en: `New status: ${body.status}`,
      });
    }

    await logAudit({ adminId: req.user!.id, action: "UPDATE_ORDER_STATUS", entity: "Order", entityId: id, changes: body, ip: req.ip });
    jsonOk(res, updated);
  })
);

adminOrdersRouter.post(
  "/:id/refund",
  requireId(),
  validateRequest({ body: refundSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof refundSchema>>, res) => {
    const id = Number(req.params.id);
    const body = req.validatedBody!;

    const order = await prisma.order.findUnique({ where: { id }, include: { items: true, user: true } });
    if (!order) throw new ApiError(404, "Order not found");
    if (!order.payment_intent_id) throw new ApiError(400, "Order has no payment intent to refund");

    const refundResult = await processStripeRefund({
      paymentIntentId: order.payment_intent_id,
      amount: body.amount,
      reason: body.reason,
    });

    await prisma.$transaction(async (tx) => {
      if (body.restock_items) {
        for (const refundItem of body.refund_items ?? []) {
          const orderItem = order.items.find((item) => item.id === refundItem.order_item_id);
          if (!orderItem) continue;
          await tx.product.update({
            where: { id: orderItem.product_id },
            data: { stock: { increment: refundItem.quantity } },
          });
        }
      }

      await tx.order.update({
        where: { id },
        data: {
          status: body.type === "full" ? OrderStatus.REFUNDED : order.status,
          payment_status: body.type === "full" ? PaymentStatus.REFUNDED : PaymentStatus.PARTIALLY_REFUNDED,
        },
      });

      const refundModel = (tx as unknown as { refundHistory?: { create: Function } }).refundHistory;
      if (refundModel) {
        await refundModel.create({
          data: {
            order_id: id,
            type: body.type,
            amount: body.amount,
            reason: body.reason,
            restock_items: body.restock_items,
            refund_provider_id: refundResult.provider_refund_id,
            created_by_admin_id: req.user!.id,
          },
        });
      }
    });

    if (order.user?.email || order.guest_email) {
      await sendBilingualEmail({
        to: order.user?.email || order.guest_email!,
        language_pref: order.user?.language_pref,
        subject_ka: `თანხის დაბრუნება: ${order.order_number}`,
        subject_en: `Refund processed: ${order.order_number}`,
        body_ka: `დაბრუნებული თანხა: ${body.amount} GEL`,
        body_en: `Refund amount: ${body.amount} GEL`,
      });
    }

    await logAudit({ adminId: req.user!.id, action: "REFUND_ORDER", entity: "Order", entityId: id, changes: body, ip: req.ip });
    jsonOk(res, { success: true, provider_refund_id: refundResult.provider_refund_id });
  })
);

adminOrdersRouter.post(
  "/:id/notes",
  requireId(),
  validateRequest({ body: orderNoteSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof orderNoteSchema>>, res) => {
    const id = Number(req.params.id);
    const noteModel = (prisma as unknown as { orderNote?: { create: Function } }).orderNote;
    if (!noteModel) throw new ApiError(500, "Order note model not configured");

    const note = await noteModel.create({
      data: {
        order_id: id,
        admin_id: req.user!.id,
        note: req.validatedBody!.note,
      },
    });

    await logAudit({ adminId: req.user!.id, action: "ADD_ORDER_NOTE", entity: "Order", entityId: id, changes: req.validatedBody, ip: req.ip });
    res.status(201).json({ data: note });
  })
);

adminOrdersRouter.get(
  "/:id/invoice",
  requireId(),
  asyncHandler(async (req: ApiRequest, res) => {
    const id = Number(req.params.id);
    const pdf = await generateInvoicePdfStub(id);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="invoice-${id}.pdf"`);
    res.send(pdf);
  })
);

adminCustomersRouter.use(authenticateToken, requireRole([UserRole.ADMIN, UserRole.SUPER_ADMIN]));

adminCustomersRouter.get(
  "/",
  validateRequest({ query: customersListQuerySchema }),
  asyncHandler(async (req: ApiRequest<unknown, z.infer<typeof customersListQuerySchema>>, res) => {
    const q = req.validatedQuery!;
    const skip = (q.page - 1) * q.limit;

    const orderBy: Prisma.UserOrderByWithRelationInput =
      q.sort_by === "created_at"
        ? { created_at: q.sort_order }
        : q.sort_by === "total_spent"
          ? { loyalty_points: q.sort_order }
          : { created_at: q.sort_order };

    const where: Prisma.UserWhereInput = {
      role: UserRole.CUSTOMER,
      ...(q.status ? { is_active: q.status === "active" } : {}),
      ...(q.search
        ? {
            OR: [
              { email: { contains: q.search, mode: "insensitive" } },
              { phone: { contains: q.search, mode: "insensitive" } },
              { first_name: { contains: q.search, mode: "insensitive" } },
              { last_name: { contains: q.search, mode: "insensitive" } },
            ],
          }
        : {}),
    };

    const [rows, total] = await prisma.$transaction([
      prisma.user.findMany({
        where,
        skip,
        take: q.limit,
        orderBy,
        include: {
          _count: { select: { orders: true } },
          orders: { select: { total: true } },
        },
      }),
      prisma.user.count({ where }),
    ]);

    jsonOk(
      res,
      rows.map((user) => ({
        id: user.id,
        name: `${user.first_name ?? ""} ${user.last_name ?? ""}`.trim(),
        email: user.email,
        phone: user.phone,
        status: user.is_active ? "active" : "blocked",
        total_orders: user._count.orders,
        total_spent: user.orders.reduce((sum, order) => sum + Number(order.total), 0),
        loyalty_points: user.loyalty_points,
        joined_date: user.created_at,
      })),
      { pagination: toPagination(q.page, q.limit, total) }
    );
  })
);

adminCustomersRouter.get(
  "/export",
  asyncHandler(async (_req, res) => {
    const fileBuffer = await generateCustomersXlsxStub();
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", 'attachment; filename="customers-export.xlsx"');
    res.send(fileBuffer);
  })
);

adminCustomersRouter.get(
  "/:id",
  requireId(),
  asyncHandler(async (req: ApiRequest, res) => {
    const id = Number(req.params.id);
    const user = await prisma.user.findUnique({
      where: { id },
      include: {
        orders: { orderBy: { created_at: "desc" }, take: 5 },
        addresses: true,
        reviews: true,
        wishlist: true,
      },
    });
    if (!user) throw new ApiError(404, "Customer not found");

    const totals = await prisma.order.aggregate({
      where: { user_id: id },
      _count: { id: true },
      _sum: { total: true },
      _avg: { total: true },
      _min: { created_at: true },
      _max: { created_at: true },
    });

    jsonOk(res, {
      user,
      stats: {
        total_orders: totals._count.id,
        total_spent: totals._sum.total ?? 0,
        avg_order_value: totals._avg.total ?? 0,
        first_order: totals._min.created_at,
        last_order: totals._max.created_at,
      },
      orders: user.orders,
      addresses: user.addresses,
      reviews: user.reviews,
      wishlist_count: user.wishlist.length,
      loyalty_points: user.loyalty_points,
    });
  })
);

adminCustomersRouter.put(
  "/:id",
  requireId(),
  validateRequest({ body: customerUpdateSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof customerUpdateSchema>>, res) => {
    const id = Number(req.params.id);
    const body = req.validatedBody!;
    const existing = await prisma.user.findUnique({ where: { id } });
    if (!existing) throw new ApiError(404, "Customer not found");

    if (body.email && req.user!.role !== UserRole.SUPER_ADMIN) {
      throw new ApiError(403, "Only SUPER_ADMIN can change email");
    }

    const updated = await prisma.user.update({
      where: { id },
      data: {
        ...(typeof body.is_active === "boolean" ? { is_active: body.is_active } : {}),
        ...(typeof body.loyalty_points === "number" ? { loyalty_points: body.loyalty_points } : {}),
        ...(body.role ? { role: body.role } : {}),
        ...(body.email ? { email: body.email } : {}),
      },
    });

    await logAudit({ adminId: req.user!.id, action: "UPDATE_CUSTOMER", entity: "User", entityId: id, changes: body, ip: req.ip });
    jsonOk(res, updated);
  })
);

adminCustomersRouter.post(
  "/:id/loyalty-points",
  requireId(),
  validateRequest({ body: loyaltyPointsSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof loyaltyPointsSchema>>, res) => {
    const id = Number(req.params.id);
    const { adjustment, reason } = req.validatedBody!;

    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) throw new ApiError(404, "Customer not found");

    const updated = await prisma.user.update({
      where: { id },
      data: { loyalty_points: { increment: adjustment } },
    });

    const loyaltyModel = (prisma as unknown as { loyaltyHistory?: { create: Function } }).loyaltyHistory;
    if (loyaltyModel) {
      await loyaltyModel.create({
        data: {
          user_id: id,
          adjustment,
          reason,
          admin_id: req.user!.id,
        },
      });
    }

    await logAudit({ adminId: req.user!.id, action: "ADJUST_LOYALTY_POINTS", entity: "User", entityId: id, changes: req.validatedBody, ip: req.ip });
    jsonOk(res, updated);
  })
);

adminCustomersRouter.put(
  "/:id/block",
  requireId(),
  validateRequest({ body: blockCustomerSchema }),
  asyncHandler(async (req: ApiRequest<z.infer<typeof blockCustomerSchema>>, res) => {
    const id = Number(req.params.id);
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) throw new ApiError(404, "Customer not found");

    await prisma.user.update({ where: { id }, data: { is_active: false } });
    const refreshModel = (prisma as unknown as { refreshToken?: { updateMany: Function } }).refreshToken;
    if (refreshModel) {
      await refreshModel.updateMany({ where: { user_id: id, is_revoked: false }, data: { is_revoked: true } });
    }

    await logAudit({ adminId: req.user!.id, action: "BLOCK_CUSTOMER", entity: "User", entityId: id, changes: req.validatedBody, ip: req.ip });
    jsonOk(res, { success: true });
  })
);

app.use("/api/v1/auth", authRouter);
app.use("/api/v1/admin/categories", adminCategoriesRouter);
app.use("/api/v1/admin/brands", adminBrandsRouter);
app.use("/api/v1/admin/orders", adminOrdersRouter);
app.use("/api/v1/admin/customers", adminCustomersRouter);

app.use((req, _res, next) => next(new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`)));

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const status = error instanceof ApiError ? error.status : 500;
  const message = error instanceof Error ? error.message : "Internal server error";
  const details = error instanceof ApiError ? error.details : undefined;

  res.status(status).json({
    success: false,
    message,
    ...(details ? { details } : {}),
  });
});

const port = Number(process.env.PORT || 4000);
app.listen(port, () => {
  console.log(`M110Beauty API running on port ${port}`);
});
