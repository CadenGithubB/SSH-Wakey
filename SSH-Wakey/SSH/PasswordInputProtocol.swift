import Foundation

/// No password is serialized into XPC. The service writes to the passed SSH pipe.
@objc protocol PasswordInputProtocol {
    func prepare(_ adapterCode: FileHandle, reply: @escaping (Bool) -> Void)
    func collect(_ channel: FileHandle, output: FileHandle, appCode: FileHandle,
                 appInfo: Data, grant: String, reply: @escaping (Bool) -> Void)
    #if DEBUG
    func probe(_ channel: FileHandle, output: FileHandle, appCode: FileHandle,
               appInfo: Data, grant: String, fixture: String, reply: @escaping (String) -> Void)
    #endif
}
