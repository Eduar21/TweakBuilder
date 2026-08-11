// TweakBuilder Tweak.xm

%hook NSObject

- (NSString *)description {
    NSLog(@"[Tweak] desc called");
    return %orig;
}

%end

%ctor {
    NSLog(@"[Tweak] Loaded!");
}
