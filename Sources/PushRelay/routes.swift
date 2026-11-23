import Vapor

func routes(_ app: Application, adminController: AdminController? = nil) throws {
    try app.register(collection: PushController())
    if let adminController {
        try app.register(collection: adminController)
    }
}
