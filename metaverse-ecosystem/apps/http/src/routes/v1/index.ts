import { Router } from "express";
import { userRouter } from "./user.routes";
import { spaceRouter } from "./space.routes";
import { adminRouter } from "./admin.routes";

export const router = Router()

router.use('/user', userRouter)
router.use('/space', spaceRouter)
router.use('/admin', adminRouter)
