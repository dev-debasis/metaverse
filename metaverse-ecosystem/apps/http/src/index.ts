import express from 'express'
import { router } from './routes/v1'
const app = express()

app.use('/api/v1', router)
app.get('/', (req, res) => {
    res.json({
        message: "Check"
    })
})
app.listen(process.env.PORT || 3000)
